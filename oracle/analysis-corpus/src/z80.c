/* Z80 CP/M .COM corpus: a few functions with calls/branch/loop for function discovery. */
unsigned char helper(unsigned char x) { return (unsigned char)(x + x + 1); }

unsigned char compute(unsigned char *arr, unsigned char n) {
    unsigned char acc = 0, i;
    for (i = 0; i < n; i++)
        acc += helper(arr[i]);
    return acc;
}

unsigned char data[3] = {1, 2, 3};

void main(void) {
    compute(data, 3);
}
