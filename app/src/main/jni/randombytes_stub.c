/* TweetNaCl 只使用 verify 路径；keypair 的随机源给一个占位实现。 */
#include <stddef.h>
void randombytes(unsigned char *buffer, unsigned long long length) {
    (void) buffer;
    (void) length;
}
