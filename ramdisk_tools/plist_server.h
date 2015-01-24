#define PLIST_MAX_SIZE    50*1024*1024

int create_listening_socket(int port);
int send_progress_message(int socket, int progress, int total);
int send_object(int socket, CFTypeRef obj);
void serve_plist_rpc(int port, CFDictionaryRef handlers);