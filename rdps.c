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
    int synS;
    int finS;
    int rstS;
    int ackR;
    int rstR;
    float elapsedTime;
} tLog;

typedef struct {
    char magic[7];
    char type[4];
    char event_type;
    int ack;
    int window;
    char sip[INET_ADDRSTRLEN];
    char spt[20];
} headerInfo;

int requestSynAck(int sock, struct sockaddr_in s_addr, struct sockaddr_in r_addr, tLog* log);
void startSender(int sock, struct sockaddr_in s_addr, struct sockaddr_in r_addr, tLog* log, FILE* fp);
int recvData(int sock, struct sockaddr_in s_addr, struct timeval start, tLog* log);
void sendRDP(int sock, char* type, int seqNum, unsigned char* payload, int size, struct sockaddr_in r_addr);
int recvRDP(int sock, headerInfo* received, struct sockaddr_in s_addr, tLog* log);
int parseRDPHeader(char* buff, headerInfo* header, struct sockaddr_in addr);
void loadDataIntoBuffer(int previous, int ackedSeq, unsigned char dataBuffer[][1000], int *sizes, int s_windowSize, FILE* fp);
void printLog(int event_type, char* sip, char* spt, char* dip, char* dpt, char* packet_type, int seqAck, int lenWin);
unsigned char* convertIntToByte(int value);
unsigned char* seekSData(FILE *fp, int offset, int bytes);
int seekIData(char* buff, int offset, int bytes);
void setSockTimeout(int sock, float seconds);
void setOptionsAndBind(int sock, struct sockaddr_in addr);
void subString(char* orig, int idx, int num);
void toLowerCase(char* str);

#define MAXSEQ 65536

char* sip;
char* spt;
char* rip;
char* rpt;
char* filePath;
int r_windowSize;
int bytesLeft;
int sentSeq;
int ackedSeq;
off_t dataOffset;

void main(int argc, char* argv[]) {
    if (argc < 6) {
        printf("Missing arguments. Correct syntax: ./rdps <sender_ip> <sender_port> <receiver_ip> <receiver_port> <sender_file_name>\n");
        exit(0);
    }
    sip = argv[1];
    spt = argv[2];
    rip = argv[3];
    rpt = argv[4];

    int s_port = (int)strtol(spt, NULL, 10);
    if (s_port <= 0) {
        printf("Sender port number invalid!\n");
        exit(0);
    }
    int r_port = (int)strtol(rpt, NULL, 10);
    if (r_port <= 0) {
        printf("Receiver port number invalid!\n");
        exit(0);
    }

    filePath = argv[5];
    FILE* fp = fopen(filePath, "rb");
    if (fp == NULL) {
        printf("Bad file path!\n");
        exit(0);
    }
    fseek(fp, 0L, SEEK_END);
    bytesLeft = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in s_addr;
    memset(&s_addr, 0, sizeof(s_addr));
    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons((uint16_t) s_port);
    inet_aton(sip, &s_addr.sin_addr);

    struct sockaddr_in r_addr;
    memset(&r_addr, 0, sizeof(r_addr));
    r_addr.sin_family = AF_INET;
    r_addr.sin_port = htons((uint16_t) r_port);
    inet_aton(rip, &r_addr.sin_addr);

    setOptionsAndBind(sock, s_addr);

    tLog log = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    struct timeval t1, t2;
    gettimeofday(&t1, NULL);

    printf("RDP sender starting at %s on port %s\n\n", sip, spt);
    int resp = requestSynAck(sock, s_addr, r_addr, &log);
    if (resp) startSender(sock, s_addr, r_addr, &log, fp);

    gettimeofday(&t2, NULL);

    log.elapsedTime = t2.tv_sec - t1.tv_sec + (t2.tv_usec - t1.tv_usec) / 1000000.0f;

    printf("\ntotal data bytes sent: %d\n", log.totalB);
    printf("unique data bytes sent: %d\n", log.uniqueB);
    printf("total data packets sent: %d\n", log.totalP);
    printf("unique data packets sent: %d\n", log.uniqueP);
    printf("SYN packets sent: %d\n", log.synS);
    printf("FIN packets sent: %d\n", log.finS);
    printf("RST packets sent: %d\n", log.rstS);
    printf("ACK packets received: %d\n", log.ackR);
    printf("RST packets received: %d\n", log.rstR);
    printf("total time duration (seconds): %f\n", log.elapsedTime);

    close(sock);
    fclose(fp);
}

// Establish the connection by sending the SYN packet. This is a two-way handshake.
int requestSynAck(int sock, struct sockaddr_in s_addr, struct sockaddr_in r_addr, tLog* log) {
    sentSeq = rand() % MAXSEQ;

    setSockTimeout(sock, 0.2);

    headerInfo received;
    int resp = -1;
    while (resp < 0) {
        sendRDP(sock, "SYN", sentSeq, NULL, 0, r_addr);
        printLog('s', sip, spt, rip, rpt, "SYN", sentSeq, 0);
        log->synS++;
        resp = recvRDP(sock, &received, s_addr, log);
    }
    r_windowSize = received.window;
    ackedSeq = received.ack;
    return resp;
}

// Begins transfering the data to the receiver
void startSender(int sock, struct sockaddr_in s_addr, struct sockaddr_in r_addr, tLog* log, FILE* fp) {
    int resend = 0;
    int s_windowSize = ceil((float)r_windowSize / 1000.0f);
    unsigned char dataBuffer[s_windowSize][1000];
    int sizes[s_windowSize];
    int i;
    for (i = 0; i < s_windowSize; i++) {
        sizes[i] = (bytesLeft < 1000) ? bytesLeft : 1000;
        if (sizes[i] == 0) continue;
        unsigned char* payload = seekSData(fp, dataOffset, sizes[i]);
        memmove(dataBuffer[i], payload, 1000);
        free(payload);
        bytesLeft -= sizes[i];
        dataOffset += sizes[i];
    }
    int toDbl = 1;

    while (bytesLeft || sizes[0]) {
        int receiverLeft = r_windowSize;
        for (i = 0; sizes[i] > 0 && sizes[i] <= receiverLeft; i++) {
            sendRDP(sock, "DAT", sentSeq, dataBuffer[i], sizes[i], r_addr);
            receiverLeft -= sizes[i];
            log->totalB += sizes[i];
            log->totalP++;
            char event_type = 'S';
            if (resend == 0) {
                event_type = 's';
                log->uniqueB += sizes[i];
                log->uniqueP++;
            } else resend -= sizes[i];
            printLog(event_type, sip, spt, rip, rpt, "DAT", sentSeq, sizes[i]);
            sentSeq = (sentSeq + sizes[i]) % MAXSEQ;
        }

        struct timeval startTime;
        gettimeofday(&startTime, NULL);
        float seconds = 0.02 * toDbl;
        startTime.tv_sec += (int)seconds;
        startTime.tv_usec += 1000000 * (seconds - (int)seconds);

        int previousAck = ackedSeq;
        int timedout = 1;
        int j;
        for (j = 0; j < i && ackedSeq != sentSeq; j++) {
            timedout = recvData(sock, s_addr, startTime, log);
            if (timedout < 1) break;
            else if (ackedSeq < timedout-1 || (sentSeq < ackedSeq && timedout-1 <= sentSeq)) ackedSeq = timedout-1;
        }
        if (timedout == 0) return;

        loadDataIntoBuffer(previousAck, ackedSeq, dataBuffer, sizes, s_windowSize, fp);
        resend = sentSeq - ackedSeq;
        if (sentSeq < ackedSeq) resend += MAXSEQ;
        if (resend > 0) toDbl *= 2;
        else toDbl = 1;
        sentSeq = ackedSeq;
    }

    setSockTimeout(sock, 0.1);
    headerInfo received;
    int resp = -1;
    for (i = 0; resp < 0 && i < 10; i++) {
        sendRDP(sock, "FIN", 0, NULL, 0, r_addr);
        log->finS++;
        printLog('s', sip, spt, rip, rpt, "FIN", 0, 0);
        do {
            resp = recvRDP(sock, &received, s_addr, log);
        } while (received.window != 0 && resp != -1);
    }
}

// Sets a timeout and listens for response from receiver. If get ACK then returns number.
int recvData(int sock, struct sockaddr_in s_addr, struct timeval start, tLog* log) {
    struct timeval now;
    gettimeofday(&now, NULL);

    float seconds = start.tv_sec - now.tv_sec + (start.tv_usec - now.tv_usec) / 1000000.0f;
    if (seconds <= 0) return -1;
    setSockTimeout(sock, seconds);

    headerInfo received;
    int resp = recvRDP(sock, &received, s_addr, log);
    if (resp < 1) return resp;
    r_windowSize = received.window;
    return received.ack + 1;
}

// Creates RDP header and sends packet to the address
void sendRDP(int sock, char* type, int seqNum, unsigned char* payload, int size, struct sockaddr_in r_addr) {
    char buffer[24 + size];
    memcpy(buffer, "CSC361", 6);
    memcpy(buffer+6, type, 3);

    unsigned char* seq = convertIntToByte(seqNum);
    memcpy(buffer+9, seq, 2);
    free(seq);

    unsigned char* length = convertIntToByte(size);
    memcpy(buffer+11, length, 4);
    free(length);

    if (size > 0) memcpy(buffer+24, payload, size);

    ssize_t bytes = sendto(sock, (void*)buffer, sizeof(buffer), 0, (struct sockaddr *)&r_addr, sizeof r_addr);
    if (bytes < 0) {
        printf("ERROR: %s\n", strerror(errno));
        close(sock);
        exit(0);
    }
}

// Listens for incoming RDP messages. Ignores non-RDP protocol. Returns -1 timeout, 0 RST, 1 ACK.
int recvRDP(int sock, headerInfo* received, struct sockaddr_in s_addr, tLog* log) {
    while (1) {
        char buff[24];
        socklen_t slen = sizeof(s_addr);
        ssize_t bytes = recvfrom(sock, (void*)buff, sizeof buff, 0, (struct sockaddr *)&s_addr, &slen);
        if (bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return -1;
            }
            printf("ERROR: %s\n", strerror(errno));
            close(sock);
            exit(0);
        }
        if (parseRDPHeader(buff, received, s_addr) < 0) continue;
        printLog('r', received->sip, received->spt, sip, spt, received->type, received->ack, received->window);
        if ((strcmp(received->sip, rip) == 0) && (strcmp(received->spt, rpt) == 0)) break;
    }
    if (strcmp(received->type, "RST") == 0) {
        log->rstR++;
        return 0;
    }
    log->ackR++;
    return 1;
}

int parseRDPHeader(char* buff, headerInfo* header, struct sockaddr_in addr) {
    memcpy(header->magic, &buff[0], 6);
    header->magic[6] = '\0';
    subString(header->magic, 0, 6);
    toLowerCase(header->magic);

    if (strcmp(header->magic, "csc361") != 0) return -1;

    memcpy(header->type, &buff[6], 3);
    header->type[3] = '\0';

    header->ack = seekIData(buff, 9, 2);
    header->window = seekIData(buff, 11, 4);

    struct in_addr copy;
    copy.s_addr = addr.sin_addr.s_addr;
    inet_ntop(AF_INET, &(copy), header->sip, INET_ADDRSTRLEN);

    snprintf(header->spt, 20, "%d", ntohs(addr.sin_port));

    return 1;
}

// Loads data from the file into sender's buffer. Similar to sender window
void loadDataIntoBuffer(int previous, int ackedSeq, unsigned char dataBuffer[][1000], int *sizes, int s_windowSize, FILE* fp) {
    int numberToLoad = ackedSeq - previous;
    if (ackedSeq < previous) numberToLoad += MAXSEQ;
    if (numberToLoad == 0) return;
    numberToLoad = ceil((float)numberToLoad / 1000.0f);
    int i;
    for (i = 0; i < s_windowSize - numberToLoad; i++) {
        memmove(dataBuffer[i], dataBuffer[i + numberToLoad], 1000);
        sizes[i] = sizes[i + numberToLoad];
    }
    for (i = s_windowSize - numberToLoad; i < s_windowSize; i++) {
        sizes[i] = (bytesLeft < 1000) ? bytesLeft : 1000;
        if (sizes[i] == 0) continue;
        unsigned char* payload = seekSData(fp, dataOffset, sizes[i]);
        memmove(dataBuffer[i], payload, 1000);
        free(payload);
        bytesLeft -= sizes[i];
        dataOffset += sizes[i];
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

//Return the string value of the data found at the offset location
unsigned char* seekSData(FILE *fp, int offset, int bytes) {
    unsigned char* buff = malloc(sizeof(unsigned char)*bytes);
    fseek(fp, offset, SEEK_SET);
    fread(buff, 1, bytes, fp);
    rewind(fp);
    return buff;
}

// Return the integer value of hex data found at the offset location
int seekIData(char* buff, int offset, int bytes) {
    int i, value = 0;
    for (i = 0; i < bytes; i++) {
        value += (unsigned int)(unsigned char)buff[i+offset] << 8*i;
    }
    return value;
}

// Sets a timeout for the socket.
void setSockTimeout(int sock, float seconds) {
    struct timeval timeout;
    timeout.tv_sec = (int)seconds;
    timeout.tv_usec = 1000000 * (seconds - (int)seconds);

    // Set the timeout
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        printf("Error: Failed to set timeout.%s\n", strerror(errno));
        close(sock);
        exit(0);
    }
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
