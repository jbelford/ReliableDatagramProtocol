/*
    Assignment #2 - Final Version
    Jack Belford
    V00829017
    Lab B03
*/

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <signal.h>
#include <ctype.h>
#include <wait.h>
#include <time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <math.h>

typedef struct {
    int totalB;
    int uniqueB;
    int totalP;
    int uniqueP;
    int synR;
    int finR;
    int rstR;
    int ackS;
    int rstS;
    struct timeval start;
    float elapsedTime;
} tLog;

typedef struct {
    char magic[7];
    char type[4];
    char event_type;
    int seq;
    int length;
    char* data;
    char sip[INET_ADDRSTRLEN];
    char spt[20];
} headerInfo;

void startReceiver(int sock, struct sockaddr_in addr, tLog* log, FILE* fp);
int parseRDPHeader(char* buff, headerInfo* header, struct sockaddr_in addr);
int processReceived(int* ackedSeq, int* readSeq, headerInfo received, tLog* log, FILE* fp);
void sendResponse(int sock, int ackedSeq, int rst, tLog* log, struct sockaddr_in addr, ssize_t slen);
void writeAndSlideWindow(FILE* fp, int index);
void printLog(int event_type, char* sip, char* spt, char* dip, char* dpt, char* packet_type, int seqAck, int lenWin);
unsigned char* convertIntToByte(int value);
int seekIData(char* buff, int offset, int bytes);
void setOptionsAndBind(int sock, struct sockaddr_in addr);
void pushSeq(int seq, int length);
int isNotable(int seq);
void subString(char* orig, int idx, int num);
void toLowerCase(char* str);

#define BUFFERSIZE 14000
#define MAXSEQ 65536

char* dip;
char* dpt;
char* filePath;
unsigned char window[BUFFERSIZE];
int notableLen;
int* notableSeqs;
int* notableSize;
int r_windowSize;

// rdpr receiver_ip receiver_port receiver_file_name
void main(int argc, char * argv[]) {
    if (argc < 4) {
        printf("Missing arguments. Correct syntax: ./rdpr <receiver_ip> <receiver_port> <receiver_file_name>\n");
        exit(0);
    }
    dip = argv[1];
    dpt = argv[2];
    int port = (int)strtol(argv[2], NULL, 10);
    if (port <= 0) {
        printf("Port number invalid!\n");
        exit(0);
    }
    filePath = argv[3];
    fopen(filePath, "wb");
    FILE* fp = fopen(filePath, "ab");
    if (fp == NULL) {
        printf("Bad file path!\n");
        exit(0);
    }
    r_windowSize = BUFFERSIZE;
    notableLen = ceil((float)BUFFERSIZE / 1000.0f);
    notableSeqs = (int*)malloc(sizeof(int)*notableLen);
    notableSize = (int*)malloc(sizeof(int)*notableLen);
    int i;
    for (i = 0; i < notableLen; i++) {
        notableSeqs[i] = -1;
        notableSize[i] = -1;
    }

    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t) port);
    inet_aton(argv[1], &addr.sin_addr);

    setOptionsAndBind(sock, addr);

    tLog log = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    printf("RDP receiver listening at %s on port %s\n\n", dip, dpt);
    startReceiver(sock, addr, &log, fp);

    struct timeval t2;
    gettimeofday(&t2, NULL);

    log.elapsedTime = t2.tv_sec - log.start.tv_sec + (t2.tv_usec - log.start.tv_usec) / 1000000.0f;

    printf("\ntotal data bytes received: %d\n", log.totalB);
    printf("unique data bytes received: %d\n", log.uniqueB);
    printf("total data packets received: %d\n", log.totalP);
    printf("unique data packets received: %d\n", log.uniqueP);
    printf("SYN packets received: %d\n", log.synR);
    printf("FIN packets received: %d\n", log.finR);
    printf("RST packets received: %d\n", log.rstR);
    printf("ACK packets sent: %d\n", log.ackS);
    printf("RST packets sent: %d\n", log.rstS);
    printf("total time duration (seconds): %f\n", log.elapsedTime);

    close(sock);
    fclose(fp);
    free(notableSeqs);
}

// Starts the receiver and begins listening to messages.
void startReceiver(int sock, struct sockaddr_in addr, tLog* log, FILE* fp) {
    socklen_t slen = sizeof(addr);
    int readSeq = 0;
    int ackedSeq = 0;
    while (log->finR < 1) {
        char buff[1024];
        ssize_t bytes = recvfrom(sock, (void*)buff, sizeof buff, 0, (struct sockaddr *)&addr, &slen);
        if (bytes < 0) {
            printf("ERROR: %s\n", strerror(errno));
            close(sock);
            exit(0);
        }

        headerInfo received;
        if (parseRDPHeader(buff, &received, addr) < 0) continue;

        int rst = processReceived(&ackedSeq, &readSeq, received, log, fp);
        if (strcmp(received.type, "RST") == 0) {
            log->rstR++;
            break;
        }
        if (received.length > 0) free(received.data);

        sendResponse(sock, ackedSeq, rst, log, addr, slen);
        printLog('s', dip, dpt, received.sip, received.spt, (rst) ? "RST" : "ACK", ackedSeq, r_windowSize);
        if (rst) break;
    }
}

// Reads the data from a received buffer using RDP format into a struct headerInfo
int parseRDPHeader(char* buff, headerInfo* header, struct sockaddr_in addr) {
    memcpy(header->magic, &buff[0], 6);
    header->magic[6] = '\0';
    subString(header->magic, 0, 6);
    toLowerCase(header->magic);

    if (strcmp(header->magic, "csc361") != 0) return -1;

    memcpy(header->type, &buff[6], 3);
    header->type[3] = '\0';

    header->seq = seekIData(buff, 9, 2);
    header->length = seekIData(buff, 11, 4);
    if (header->length > 0) {
        header->data = (char *)malloc(sizeof(char)*(header->length));
        memcpy(header->data, &buff[24], header->length);
    }

    struct in_addr copy;
    copy.s_addr = addr.sin_addr.s_addr;
    inet_ntop(AF_INET, &(copy), header->sip, INET_ADDRSTRLEN);

    snprintf(header->spt, 20, "%d", ntohs(addr.sin_port));

    return 0;
}

// Processes the received data and decides what to do based on the type of message
int processReceived(int* ackedSeq, int* readSeq, headerInfo received, tLog* log, FILE* fp) {
    int rst = 0;
    received.event_type = 'r';
    if (strcmp(received.type, "SYN") == 0) {
        *ackedSeq = received.seq;
        *readSeq = received.seq;
        gettimeofday(&log->start, NULL);
        log->synR++;
    } else if (strcmp(received.type, "DAT") == 0) {
        log->totalP++;
        log->totalB += received.length;
        int max = (*(readSeq) + BUFFERSIZE) % MAXSEQ;
        int slot = received.seq - *readSeq;
        int ackSlot = *ackedSeq - *readSeq;
        if (slot < 0) slot += MAXSEQ;
        if (ackSlot < 0) ackSlot += MAXSEQ;

        if (slot + received.length > BUFFERSIZE || slot < ackSlot || (slot > ackSlot && isNotable(received.seq) > -1)) {
            received.event_type = 'R';
        } else {
            log->uniqueP++;
            log->uniqueB += received.length;
            memmove(window + slot, received.data, received.length);
            pushSeq(received.seq, received.length);
            if (received.seq == *ackedSeq) {
                int index = *ackedSeq - *readSeq;
                if (*ackedSeq < *readSeq) index += MAXSEQ;
                while (index < BUFFERSIZE && isNotable(*ackedSeq) > -1) {
                    int size = isNotable(*ackedSeq);
                    if (size < 1) break;
                    *ackedSeq = (*ackedSeq + size) % MAXSEQ;
                    index += size;
                }
                if (index + 1000.0f > BUFFERSIZE) {
                    writeAndSlideWindow(fp, index);
                    r_windowSize = BUFFERSIZE;
                    *readSeq = *ackedSeq;
                } else {
                    r_windowSize = BUFFERSIZE - index;
                }
            }
        }
    } else if (strcmp(received.type, "FIN") == 0) {
        log->finR++;
        int size = *ackedSeq - *readSeq;
        if (*ackedSeq < *readSeq) size += MAXSEQ;
        writeAndSlideWindow(fp, size);
        *ackedSeq = 0;
        *readSeq = 0;
        r_windowSize = 0;
    }

    printLog(received.event_type, received.sip, received.spt, dip, dpt, received.type,
        received.seq, received.length);

    return rst;
}

// Sends an RDP response to the previous sender
void sendResponse(int sock, int ackedSeq, int rst, tLog* log, struct sockaddr_in addr, ssize_t slen) {
    char buffer[25];
    memcpy(buffer, "CSC361", 6);

    if (rst) {
        log->rstS++;
        memcpy(buffer+6, "RST", 3);
    } else {
        log->ackS++;
        memcpy(buffer+6, "ACK", 3);
    }

    unsigned char* ack = convertIntToByte(ackedSeq);
    memcpy(buffer+9, ack, 2);
    free(ack);

    unsigned char* wSize = convertIntToByte(r_windowSize);
    memcpy(buffer+11, wSize, 4);
    free(wSize);

    ssize_t bytes = sendto(sock, (void*)buffer, sizeof(buffer), 0, (struct sockaddr *)&addr, slen);
    if (bytes < 0) {
        printf("ERROR: %s\n", strerror(errno));
        exit(0);
    }
}

// Writes the data in stored packets to the file and slides the window
void writeAndSlideWindow(FILE* fp, int index) {
    fwrite(window, sizeof(unsigned char), index, fp);
    int i;
    for (i = 0; i < BUFFERSIZE - index; i++) {
        window[i] = window[i + index];
    }
}

// Print the log message
void printLog(int event_type, char* sip, char* spt, char* dip, char* dpt, char* packet_type, int seqAck, int lenWin) {
    struct timeval currentTime;
    gettimeofday(&currentTime, NULL);
    int microSeconds = (int)(currentTime.tv_usec % 1000000);

    time_t current_time;
    struct tm * time_info;
    char time_string[9];
    time(&current_time);
    time_info = localtime(&current_time);
    strftime(time_string, sizeof(time_string), "%H:%M:%S", time_info);
    printf("%s.%d %c %s:%s %s:%s %s %d %d\n", time_string, microSeconds, event_type, sip, spt,
        dip, dpt, packet_type, seqAck, lenWin);
}

// Converts an integer into an array of bytes
unsigned char* convertIntToByte(int value) {
    unsigned char* bytes = (unsigned char*)malloc(sizeof(unsigned char)*4);
    bytes[0] = value & 0xFF;
    bytes[1] = (value >> 8) & 0xFF;
    bytes[2] = (value >> 16) & 0xFF;
    bytes[3] = (value >> 24) & 0xFF;
    return bytes;
}

//Return the integer value of hex data found at the offset location
int seekIData(char* buff, int offset, int bytes) {
    int i, value = 0;
    for (i = 0; i < bytes; i++) {
        value += (unsigned int)(unsigned char)buff[i+offset] << 8*i;
    }
    return value;
}

// Sets options on the socket and binds to the address
void setOptionsAndBind(int sock, struct sockaddr_in addr) {
    // Allow reuse of previous address
    int on = 1;
    if (setsockopt(sock,SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        printf("Error: Failed to reuse address.%s\n", strerror(errno));
        close(sock);
        exit(0);
    }
    //Bind the socket to the address
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        printf("Error: Failed to bind.%s\n", strerror(errno));
        close(sock);
        exit(0);
    }
}

// Push a sequence number into the list of notable sequence numbers
void pushSeq(int seq, int length) {
    int i;
    for (i = 0; i < notableLen; i++) {
        if (notableSeqs[i] == -1) {
            notableSeqs[i] = seq;
            notableSize[i] = length;
            return;
        }
    }
    for (i = 0; i < notableLen - 1; i++) {
        notableSeqs[i] = notableSeqs[i + 1];
        notableSize[i] = notableSize[i + 1];
    }
    notableSeqs[notableLen - 1] = seq;
    notableSize[notableLen - 1] = length;
}

// Check if the sequence number is notable (Data for it is already stored in buffer)
int isNotable(int seq) {
    int i;
    for (i = 0; i < notableLen; i++) {
        if (notableSeqs[i] == seq) {
            return notableSize[i];
        }
    }
    return -1;
}

// Returns a substring of the orig
void subString(char* orig, int idx, int num) {
    if (strlen(orig) < num) return;
    int i;
    for (i = 0; i < idx; i++) {
        orig[i] = '\0';
    }
    for (i = idx+num; orig[i] != '\0'; i++) {
        orig[i] = '\0';
    }
}

//Makes a string lower case
void toLowerCase(char* str) {
    int i;
    for (i = 0; i < strlen(str); i++) {
        str[i] = (char)tolower(str[i]);
    }
}
