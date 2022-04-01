#include <stdlib.h>
#include <unistd.h>

int main(){
    while(1){
        system("curl www.baidu.com -o /dev/null -s");
        sleep(0.5);
    }
    return 0;
}