#include <stdlib.h>
#include <unistd.h>

int main(){
    for(int i = 0;i < 10000000;++i){
        malloc(1024);
    }
    sleep(10);
    return 0;
}