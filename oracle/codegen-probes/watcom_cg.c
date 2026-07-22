unsigned char g;
int cmpbyte(unsigned char c){ if (c == 5) return 1; return 0; }
int loop(int n){ int s=0,i; for(i=0;i<n;i++) s+=i; return s; }
int sw(int x){ switch(x){case 0:return 1;case 1:return 2;case 2:return 4;default:return 8;} }
