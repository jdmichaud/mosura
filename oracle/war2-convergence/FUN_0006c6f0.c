#pragma aux FUN_0006c6f0 parm caller [] modify [eax ecx edx ebx];
extern int func_0x00051ea6();
#pragma aux func_0x00051ea6 parm caller [];
extern int func_0x00054c8a();
#pragma aux func_0x00054c8a parm caller [];
extern int func_0x00055c5a();
#pragma aux func_0x00055c5a parm caller [];
extern int func_0x0005ee67();
extern int func_0x0006b650();
#pragma aux func_0x0006b650 parm caller [];
extern int func_0x0006b880();
#pragma aux func_0x0006b880 parm caller [];
extern int func_0x0006bd80();
#pragma aux func_0x0006bd80 parm caller [];
extern int func_0x0006c6b0();
#pragma aux func_0x0006c6b0 parm caller [];
int iRam000a875c;
struct s30 { char b[0x1e]; };
int *piRam000a8770;
int iRam00089fb8;
int iRam000a8750;
int iRam000a86a8;
int iRam000a8744;
int iRam000a874c;
int iRam000a8754;
int iRam000a8758;
int iRam000a8764;
unsigned int uRam000a8748;
unsigned int uRam000a8760;
unsigned int uRam000a8768;
unsigned int uRam000a876c;

void FUN_0006c6f0(volatile int4 param_1)
{
  uint4 uVar11;
  uint1 uVar20;
  int4 * piVar24;
  int4 * piVar35;
  uint4 uVar30;
  int4 * piVar33;
  int4 * piVar5;
  int4 iVar36;
  uint4 uVar25;
  int4 * piVar6;
  int4 * piVar30;
  int4 iVar32;
  uint1 * puVar9;
  xunknown4 xVar19;
  int4 iVar31;
  xunknown1 * pxVar10;
  int4 * piVar27;
  int4 * piVar1;
  int4 xBuf [3];
  int4 * piVar2;
  int4 * piVar26;
  uint4 uVar22;
  int4 * piVar23;
  xunknown4 * pxVar16;
  int4 iVar34;
  int4 iVar14;
  int4 * piVar21;
  uint1 uVar18;
  int4 * piVar8;
  xunknown4 * pxVar17;
  int4 * piVar3;
  int4 * piVar12;
  int4 * piVar13;
  uint4 uVar29;
  int4 iQ;
  int4 iVar7;
  int4 iVar4;
  int4 iVar15;
  int4 iVar28;

  iQ = param_1;
  if ((*((int4 *)(iQ + 0x14)) == 0) && (iRam00089fb8 == 0)) {
    iVar4 = 1;
    iRam000a8754 = *((int4 *)(iQ + 0x1c));
    iRam00089fb8 = iVar4;
    iQ = param_1;
    piRam000a8770 = (int4 *)*((xunknown4 *)(iQ + 0x18));
    if (iRam000a8754 != 0) {
      do {
        piVar3 = piRam000a8770;
        if (piRam000a8770[1] == 4) {
          iVar4 = piRam000a8770[0xd];
          iVar31 = piRam000a8770[0x12];
          iVar32 = piRam000a8770[0x16];
          piRam000a8770[0xd] = iVar4 + 1;
          iRam000a8764 = 0;
          piRam000a8770[0x16] = iVar32 + iVar31;
        LAB_0006c767:
          iVar4 = piRam000a8770[0x16];
          if (iVar4 < 100) goto LAB_0006cd53;
          {
            iVar34 = iVar4 - 100;
            iVar7 = piRam000a8770[0x155];
            piRam000a8770[0x16] = iVar34;
            if (0 < iVar7) {
              iRam000a874c = 0;
              iVar28 = -1;
              iVar36 = iRam000a874c;
              do {
                if (piRam000a8770[iRam000a874c + 0x156] != iVar28) {
                  iVar34 = piRam000a8770[iRam000a874c + 0x196] + iVar28;
                  piRam000a8770[iRam000a874c + 0x196] = iVar34;
                  if (iVar34 <= iVar36) {
                    func_0x0006bd80(piRam000a8770, piRam000a8770[iRam000a874c + 0x156] | 0x80, piRam000a8770[iRam000a874c + 0x176], iVar36, iVar36);
                    piRam000a8770[iRam000a874c + 0x156] = iVar28;
                    iVar34 = piRam000a8770[0x155] + iVar28;
                    piRam000a8770[0x155] = iVar34;
                    if (iVar36 == iVar34) break;
                  }
                }
                iRam000a874c = iRam000a874c + 1;
              } while (iRam000a874c < 0x20);
            }
            iVar7 = piRam000a8770[0xc] - 1;
            piRam000a8770[0xc] = iVar7;
            if (iVar7 <= 0) {
              do {
                while( true ) {
                LAB_0006c839:
                  piVar8 = piRam000a8770;
                  puVar9 = (uint1 *)piRam000a8770[5];
                  uVar29 = *puVar9;
                  uRam000a8760 = uVar29;
                  if (uVar29 < 0x80) goto LAB_0006cca9;
                  if (iRam000a8764 != 0) goto LAB_0006cca9;
                  switch (uRam000a8760) {
                    case 0xf0:
                    case 0xf7:
                      goto LAB_0006ca6f;
                    case 0xff:
                      break;
                    default:
                      goto LAB_0006cb0c;
                  }
                  break;
                }
                {
                  puVar9 = puVar9 + 2;
                  uRam000a876c = puVar9[-1];
                  piVar5 = piRam000a8770 + 5;
                  *piVar5 = (int4)puVar9;
                  uRam000a8768 = func_0x0006b880(piVar5);
                  uVar29 = uRam000a876c;
                  piVar21 = piRam000a8770;
                  switch (uVar29) {
                    case 0x2f: {
                      iVar4 = 1;
                      iRam000a8764 = iVar4;
                      iVar7 = piRam000a8770[0xb];
                      if (iVar7 != 0) {
                        iVar34 = iVar7 - iVar4;
                        piRam000a8770[0xb] = iVar34;
                        if (iVar34 == 0) goto LAB_0006c935;
                      }
                      piRam000a8770[0x17] = 0;
                      piRam000a8770[0x18] = -1;
                      iVar7 = piRam000a8770[4] + 8;
                      piRam000a8770[0x1b] = 0;
                      iVar4 = piRam000a8770[9];
                      piRam000a8770[5] = iVar7;
                      if (iVar4 != 0) {
                        (*((int (__cdecl *)(int4, int4, int4, int4))piRam000a8770[9]))(*piRam000a8770, (int4)piRam000a8770, 0, 0);
                      }
                      goto LAB_0006ca57;
                    LAB_0006c935:
                      func_0x00054c8a(piRam000a8770);
                      iVar4 = piRam000a8770[10];
                      piRam000a8770[1] = 2;
                      if (iVar4 != 0) {
                        (*((int (__cdecl *)(int4))piRam000a8770[10]))((int4)piRam000a8770);
                        piRam000a8770[5] = piRam000a8770[5] + uRam000a8768;
                        goto LAB_0006c839;
                      }
                      goto LAB_0006ca57;
                    }
                    case 0x51: {
                      puVar9 = (uint1 *)piRam000a8770[5];
                      iVar7 = *puVar9;
                      iVar31 = puVar9[1];
                      iVar32 = puVar9[2];
                      iRam000a875c = iVar7 * 0x10000 + iVar31 * 0x100 + iVar32;
                      piRam000a8770[0x1c] = iRam000a875c * 0x10;
                      piRam000a8770[5] = piRam000a8770[5] + uRam000a8768;
                      goto LAB_0006c839;
                    }
                    case 0x58: {
                      piRam000a8770[0x19] = *((uint1 *)piRam000a8770[5]);
                      iVar7 = *((uint1 *)(piRam000a8770[5] + 1));
                      iRam000a875c = iVar7 - 2;
                      iRam000a8758 = 16000000 / iRam000a86a8;
                      if (iRam000a875c < 0) {
                        iRam000a875c = -iRam000a875c;
                        iVar28 = iRam000a8758 >> (uint1)iRam000a875c;
                      }
                      else {
                        iVar28 = iRam000a8758 << (uint1)iRam000a875c;
                      }
                      piVar24 = piRam000a8770;
                      piRam000a8770[0x1a] = iVar28;
                      piRam000a8770[0x1b] = 0;
                      piVar24[0x17] = 0;
                      piVar24[0x18] = piVar24[0x18] + 1;
                      iVar4 = piVar24[9];
                      piVar24[0x1b] = piVar24[0x1b] - piVar24[0x1a];
                      if (iVar4 != 0) {
                        (*((int (__cdecl *)(int4, int4, int4, int4))piVar24[9]))(*piVar24, (int4)piVar24, piVar24[0x17], piVar24[0x18]);
                      }
                    }
                  }
                LAB_0006ca57:
                  piRam000a8770[5] = piRam000a8770[5] + uRam000a8768;
                  goto LAB_0006c839;
                }
              LAB_0006ca6f:
                iRam000a8744 = piRam000a8770[5] + 1;
                uRam000a8768 = func_0x0006b880(0xa8744);
                iVar4 = piRam000a8770[5];
                uRam000a8768 = uRam000a8768 + (iRam000a8744 - iVar4);
                uVar29 = uRam000a8768;
                iQ = param_1;
                func_0x0006b650(iQ);
                if (0x200 < uVar29) {
                  uVar30 = 0x200;
                }
                else {
                  uVar30 = uVar29;
                }
                func_0x0005ee67(*((int4 *)(iQ + 8)) + 0x100, iVar4, uVar30);
                *((int4 *)(iQ + 0x1a8)) = *((int4 *)(iQ + 0x1a8)) + 1;
                func_0x0006b650(iQ);
                piRam000a8770[5] = piRam000a8770[5] + uRam000a8768;
              } while( true );
            }
            goto LAB_0006ccc4;
                LAB_0006cb0c:
                  uRam000a8760 = uRam000a8760 & 0xf0;
                  pxVar10 = (xunknown1 *)piRam000a8770[5];
                  uVar11 = uRam000a8748;
                  piVar12 = piRam000a8770;
                  func_0x0006bd80(piRam000a8770, *pxVar10, pxVar10[1], pxVar10[2], 1);
                  if (uRam000a8760 != 0x90) {
                    switch ((int4)*((uint1 *)piRam000a8770[5]) & 0xf0) {
                      case 0x80:
                      case 0x90:
                      case 0xa0:
                      case 0xb0:
                      case 0xe0:
                        iVar7 = 3;
                        break;
                      case 0xc0:
                      case 0xd0:
                        iVar7 = 2;
                        break;
                      default:
                        iVar7 = 0;
                        break;
                    }
                    piRam000a8770[5] = piRam000a8770[5] + iVar7;
                    goto LAB_0006c839;
                  }
                  {
                    iVar7 = 0;
                    iRam000a874c = 0;
                    do {
                      if (*(int4 *)((int4)piRam000a8770 + iVar7 + 0x558) == -1) break;
                      iRam000a874c = iRam000a874c + 1;
                      iVar7 = iVar7 + 4;
                    } while (iVar7 < 0x80);
                    iVar14 = iRam000a874c;
                    if (iRam000a874c == 0x20) {
                      *(struct s30 *)0xa8578 = *(struct s30 *)0x8eb00;
                      func_0x00054c8a(piRam000a8770);
                      iRam00089fb8 = 0;
                      piRam000a8770[1] = 2;
                      goto LAB_0006ce9a;
                    }
                    piRam000a8770[0x155] = piRam000a8770[0x155] + 1;
                    piVar12[iVar14 + 0x156] = uVar11;
                    piVar12[iVar14 + 0x176] = *((uint1 *)(piVar12[5] + 1));
                    piVar12[5] = piVar12[5] + 3;
                    xVar19 = func_0x0006b880(piVar12 + 5);
                    piRam000a8770[iRam000a874c + 0x196] = xVar19;
                  }
                goto LAB_0006c839;
          }
LAB_0006cca9:
          if (iRam000a8764 == 0) {
            puVar9 = (uint1 *)piRam000a8770[5];
            piRam000a8770[5] = (int4)(puVar9 + 1);
            piRam000a8770[0xc] = *puVar9;
          }
        LAB_0006ccc4:
          if (iRam000a8764 != 0) goto LAB_0006c767;
          piVar35 = piRam000a8770;
          iVar32 = piRam000a8770[0x1b] + piRam000a8770[0x1a];
          iVar4 = piRam000a8770[0x1c];
          piRam000a8770[0x1b] = iVar32;
          if (iVar4 <= iVar32) {
            piVar35[0x1b] = iVar32 - iVar4;
            piVar35[0x17] = piVar35[0x17] + 1;
            if (piVar35[0x19] <= piVar35[0x17] + 1) {
              piVar35[0x17] = 0;
              piVar35[0x18] = piVar35[0x18] + 1;
            }
            if (piRam000a8770[9] != 0) {
              func_0x00055c5a(piRam000a8770, &iRam000a874c, &iRam000a8750);
              (*((int (__cdecl *)(int4, int4, int4, int4))piRam000a8770[9]))(*piRam000a8770, (int4)piRam000a8770, iRam000a874c, iRam000a8750);
            }
          }
        LAB_0006cd53:
          if (iRam000a8764 == 0) {
            if (piRam000a8770[0xe] != piRam000a8770[0xf]) {
              iVar4 = *piRam000a8770;
              piRam000a8770[0x10] = piRam000a8770[0x10] + *((int4 *)(iVar4 + 0x10));
              do {
                piVar30 = piRam000a8770;
                iVar4 = piRam000a8770[0x10];
                iVar31 = piRam000a8770[0x11];
                if (iVar4 < iVar31) break;
                iVar32 = piRam000a8770[0xe];
                piRam000a8770[0x10] = iVar4 - iVar31;
                if (iVar32 < piRam000a8770[0xf]) {
                  piVar30[0xe] = iVar32 + 1;
                }
                else {
                  piVar30[0xe] = iVar32 + -1;
                }
              } while (piRam000a8770[0xe] != piRam000a8770[0xf]);
              if ((piRam000a8770[0xd] & 7) == 0) {
                func_0x0006c6b0(piRam000a8770);
              }
            }
            if (piRam000a8770[0x12] != piRam000a8770[0x13]) {
              iVar4 = *piRam000a8770;
              piRam000a8770[0x14] = piRam000a8770[0x14] + *((int4 *)(iVar4 + 0x10));
              do {
                piVar33 = piRam000a8770;
                iVar4 = piRam000a8770[0x14];
                iVar31 = piRam000a8770[0x15];
                if (iVar4 < iVar31) break;
                iVar32 = piRam000a8770[0x12];
                piRam000a8770[0x14] = iVar4 - iVar31;
                if (iVar32 < piRam000a8770[0x13]) {
                  piVar33[0x12] = iVar32 + 1;
                }
                else {
                  piVar33[0x12] = iVar32 + -1;
                }
              } while (piRam000a8770[0x12] != piRam000a8770[0x13]);
            }
          }
        }
        iRam000a8754 = iRam000a8754 + -1;
        piRam000a8770 = piRam000a8770 + 0x1c6;
      } while (iRam000a8754 != 0);
    }
    iQ = param_1;
    if (0 < *((int4 *)(iQ + 0x1a8))) {
      *((int2 *)(xBuf + 1)) = (int2)*((int4 *)(iQ + 0x1a8));
      func_0x00051ea6(*((int4 *)param_1), 0x502, xBuf, 0);
      iQ = param_1;
      *((xunknown4 *)(iQ + 0x1a8)) = 0;
      *((xunknown4 *)(iQ + 0x1ac)) = 0;
    }
    iRam00089fb8 = 0;
  }
LAB_0006ce9a:
  return;
}
