Class: Lcom/badoo/mobile/android/BadooActivity;
AccessFlags: public final 
SuperType: Lb/a4h;
Interfaces: [Lb/i2e$a;]
SourceFile: SOURCE:SourceFile
# 1 annotations
.annotation runtime Lkotlin/Metadata;
.end annotation


# fields
.field public static final O : Lcom/badoo/smartresources/b$a;
    .annotation build Lorg/jetbrains/annotations/NotNull;
    .end annotation
.field public static final P : Lcom/badoo/smartresources/b$a;
    .annotation build Lorg/jetbrains/annotations/NotNull;
    .end annotation
.field public static final Q : Lb/j4e;
    .annotation build Lorg/jetbrains/annotations/NotNull;
    .end annotation
.field public final        K : Lb/j4e;
    .annotation build Lorg/jetbrains/annotations/NotNull;
    .end annotation
.field public              N : Lb/ol8;


.method static <clinit>()V
    .registers 2

                               .line 1
    005b1520: 2200 586c               0000: new-instance        v0, Lcom/badoo/smartresources/b$a; # type@6c58
                               .line 3
    005b1524: 1301 be00               0002: const/16            v1, 0xbe
                               .line 5
    005b1528: 7020 def5 1000          0004: invoke-direct       {v0, v1}, Lcom/badoo/smartresources/b$a;-><init>(I)V # method@f5de
                               .line 8
    005b152e: 6900 169f               0007: sput-object         v0, Lcom/badoo/mobile/android/BadooActivity;->O:Lcom/badoo/smartresources/b$a; # field@9f16
                              .line 10
    005b1532: 2200 586c               0009: new-instance        v0, Lcom/badoo/smartresources/b$a; # type@6c58
                              .line 12
    005b1536: 7020 def5 1000          000b: invoke-direct       {v0, v1}, Lcom/badoo/smartresources/b$a;-><init>(I)V # method@f5de
                              .line 15
    005b153c: 6900 179f               000e: sput-object         v0, Lcom/badoo/mobile/android/BadooActivity;->P:Lcom/badoo/smartresources/b$a; # field@9f17
                              .line 17
    005b1540: 2200 003a               0010: new-instance        v0, Lb/qp; # type@3a00
                              .line 19
    005b1544: 1211                    0012: const/4             v1, 0x1
                              .line 20
    005b1546: 7020 f67c 1000          0013: invoke-direct       {v0, v1}, Lb/qp;-><init>(I)V # method@7cf6
                              .line 23
    005b154c: 7110 9772 0000          0016: invoke-static       {v0}, Lb/p6e;->b(Lkotlin/jvm/functions/Function0;)Lb/j4e; # method@7297
                              .line 26
    005b1552: 0c00                    0019: move-result-object  v0
                              .line 27
    005b1554: 6900 189f               001a: sput-object         v0, Lcom/badoo/mobile/android/BadooActivity;->Q:Lb/j4e; # field@9f18
                              .line 61
    005b1558: 0e00                    001c: return-void         
    
.end method

.method public <init>()V
    .registers 3

                               .line 1
    005b156c: 7010 0108 0200          0000: invoke-direct       {v2}, Lb/a4h;-><init>()V # method@0801
                               .line 4
    005b1572: 2200 d155               0003: new-instance        v0, Lb/z8; # type@55d1
                               .line 6
    005b1576: 1241                    0005: const/4             v1, 0x4
                               .line 7
    005b1578: 7030 d3b2 2001          0006: invoke-direct       {v0, v2, v1}, Lb/z8;-><init>(Ljava/lang/Object;, I)V # method@b2d3
                              .line 10
    005b157e: 7110 9772 0000          0009: invoke-static       {v0}, Lb/p6e;->b(Lkotlin/jvm/functions/Function0;)Lb/j4e; # method@7297
                              .line 13
    005b1584: 0c00                    000c: move-result-object  v0
                              .line 14
    005b1586: 5b20 149f               000d: iput-object         v0, v2, Lcom/badoo/mobile/android/BadooActivity;->K:Lb/j4e; # field@9f14
                              .line 17
    005b158a: 0e00                    000f: return-void         
    
.end method

.method public final B2()Lb/hah;
    .annotation build Lorg/jetbrains/annotations/NotNull;
    .end annotation

    .registers 2

                               .line 1
    005b14f4: 6200 8628               0000: sget-object         v0, Lb/hah;->d:Lb/hah; # field@2886
                              .line 17
    005b14f8: 1100                    0002: return-object       v0
    
.end method

.method public final G2(Landroid/os/Bundle;)V
    .registers 5

                               .line 1
    005b1638: 6200 d287               0000: sget-object         v0, Lb/yq1;->a:[Lb/yq1; # field@87d2
                               .line 3
    005b163c: 6200 ef58               0002: sget-object         v0, Lb/pr0;->o:Lb/ad7; # field@58ef
                               .line 5
    005b1640: 3800 0300               0004: if-eqz              v0, :cond_0007
                               .line 7
    005b1644: 2802                    0006: goto                :goto_0008
                               .line 8
                            cond_0007:
    005b1646: 1200                    0007: const/4             v0, 0
                               .line 9
                            goto_0008:
    005b1648: 6e10 9209 0000          0008: invoke-virtual      {v0}, Lb/ad7;->E()Lb/fy0; # method@0992
                              .line 12
    005b164e: 0c00                    000b: move-result-object  v0
                              .line 13
    005b1650: 6101 ed32               000c: sget-wide           v1, Lb/jg2;->k:J # field@32ed
                              .line 15
    005b1654: 7230 a430 1002          000e: invoke-interface    {v0, v1, v2}, Lb/fy0;->c(J)V # method@30a4
                              .line 18
    005b165a: 6e10 0ef3 0300          0011: invoke-virtual      {p0}, Lcom/badoo/mobile/ui/b;->getIntent()Landroid/content/Intent; # method@f30e
                              .line 21
    005b1660: 0c00                    0014: move-result-object  v0
                              .line 22
    005b1662: 1a01 69b9               0015: const-string        v1, "getIntent(...)" # string@b969
                              .line 24
    005b1666: 7120 64ff 1000          0017: invoke-static       {v0, v1}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullExpressionValue(Ljava/lang/Object;, Ljava/lang/String;)V # method@ff64
                              .line 27
    005b166c: 6200 720e               001a: sget-object         v0, Lb/cnp;->a:Lb/cnp$a; # field@0e72
                              .line 29
    005b1670: 6e10 e7fc 0000          001c: invoke-virtual      {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class; # method@fce7
                              .line 32
    005b1676: 6201 189f               001f: sget-object         v1, Lcom/badoo/mobile/android/BadooActivity;->Q:Lb/j4e; # field@9f18
                              .line 34
    005b167a: 7210 584b 0100          0021: invoke-interface    {v1}, Lb/j4e;->getValue()Ljava/lang/Object; # method@4b58
                              .line 37
    005b1680: 0c01                    0024: move-result-object  v1
                              .line 38
    005b1682: 1f01 8e6f               0025: check-cast          v1, Ljava/lang/String; # type@6f8e
                              .line 40
    005b1686: 6e10 e7fc 0000          0027: invoke-virtual      {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class; # method@fce7
                              .line 43
    005b168c: 6f20 09f3 4300          002a: invoke-super        {p0, v4}, Lcom/badoo/mobile/ui/b;->G2(Landroid/os/Bundle;)V # method@f309
                              .line 79
    005b1692: 0e00                    002d: return-void         
    
.end method

.method public final H0()V
    .registers 3

                               .line 1
    005b18d8: 2200 f028               0000: new-instance        v0, Lb/ln1; # type@28f0
                               .line 3
    005b18dc: 1201                    0002: const/4             v1, 0
                               .line 4
    005b18de: 7030 7c5b 2001          0003: invoke-direct       {v0, v2, v1}, Lb/ln1;-><init>(Ljava/lang/Object;, I)V # method@5b7c
                               .line 7
    005b18e4: 6e20 5000 0200          0006: invoke-virtual      {v2, v0}, Landroid/app/Activity;->runOnUiThread(Ljava/lang/Runnable;)V # method@0050
                              .line 17
    005b18ea: 0e00                    0009: return-void         
    
.end method

.method public final H2(Landroid/os/Bundle;)V
    .registers 5

                               .line 1
    005b16a4: 6f20 0af3 4300          0000: invoke-super        {p0, v4}, Lcom/badoo/mobile/ui/b;->H2(Landroid/os/Bundle;)V # method@f30a
                               .line 4
    005b16aa: 1404 b901 0d7f          0003: const               v4, 0x7f0d01b9
                               .line 7
    005b16b0: 6e20 1df3 4300          0006: invoke-virtual      {p0, v4}, Lcom/badoo/mobile/ui/b;->setContentView(I)V # method@f31d
                              .line 10
    005b16b6: 1404 650d 0a7f          0009: const               v4, 0x7f0a0d65
                              .line 13
    005b16bc: 6e20 332d 4300          000c: invoke-virtual      {p0, v4}, Lb/fm0;->findViewById(I)Landroid/view/View; # method@2d33
                              .line 16
    005b16c2: 0c04                    000f: move-result-object  v4
                              .line 17
    005b16c4: 1f04 2558               0010: check-cast          v4, Lcom/airbnb/lottie/LottieAnimationView; # type@5825
                              .line 19
    005b16c8: 3804 2e00               0012: if-eqz              v4, :cond_0040
                              .line 21
    005b16cc: 6e10 0804 0400          0014: invoke-virtual      {v4}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams; # method@0408
                              .line 24
    005b16d2: 0c00                    0017: move-result-object  v0
                              .line 25
    005b16d4: 3800 1500               0018: if-eqz              v0, :cond_002d
                              .line 27
    005b16d8: 6201 179f               001a: sget-object         v1, Lcom/badoo/mobile/android/BadooActivity;->P:Lcom/badoo/smartresources/b$a; # field@9f17
                              .line 29
    005b16dc: 7120 d6f5 3100          001c: invoke-static       {v1, p0}, Lcom/badoo/smartresources/a;->l(Lcom/badoo/smartresources/b;, Landroid/content/Context;)I # method@f5d6
                              .line 32
    005b16e2: 0a01                    001f: move-result         v1
                              .line 33
    005b16e4: 5901 7600               0020: iput                v1, v0, Landroid/view/ViewGroup$LayoutParams;->width:I # field@0076
                              .line 35
    005b16e8: 6201 169f               0022: sget-object         v1, Lcom/badoo/mobile/android/BadooActivity;->O:Lcom/badoo/smartresources/b$a; # field@9f16
                              .line 37
    005b16ec: 7120 d6f5 3100          0024: invoke-static       {v1, p0}, Lcom/badoo/smartresources/a;->l(Lcom/badoo/smartresources/b;, Landroid/content/Context;)I # method@f5d6
                              .line 40
    005b16f2: 0a01                    0027: move-result         v1
                              .line 41
    005b16f4: 5901 7500               0028: iput                v1, v0, Landroid/view/ViewGroup$LayoutParams;->height:I # field@0075
                              .line 43
    005b16f8: 6e20 6e04 0400          002a: invoke-virtual      {v4, v0}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V # method@046e
                              .line 46
                            cond_002d:
    005b16fe: 2200 1422               002d: new-instance        v0, Lb/jn1; # type@2214
                              .line 48
    005b1702: 7030 f44d 3004          002f: invoke-direct       {v0, p0, v4}, Lb/jn1;-><init>(Lcom/badoo/mobile/android/BadooActivity;, Lcom/airbnb/lottie/LottieAnimationView;)V # method@4df4
                              .line 51
    005b1708: 6e10 55b7 0400          0032: invoke-virtual      {v4}, Lcom/airbnb/lottie/LottieAnimationView;->getComposition()Lb/s1f; # method@b755
                              .line 54
    005b170e: 0c01                    0035: move-result-object  v1
                              .line 55
    005b1710: 3801 0500               0036: if-eqz              v1, :cond_003b
                              .line 57
    005b1714: 6e10 f54d 0000          0038: invoke-virtual      {v0}, Lb/jn1;->a()V # method@4df5
                              .line 60
                            cond_003b:
    005b171a: 5444 e88f               003b: iget-object         v4, v4, Lcom/airbnb/lottie/LottieAnimationView;->l:Ljava/util/HashSet; # field@8fe8
                              .line 62
    005b171e: 6e20 61fe 0400          003d: invoke-virtual      {v4, v0}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z # method@fe61
                              .line 65
                            cond_0040:
    005b1724: 6e10 4600 0300          0040: invoke-virtual      {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window; # method@0046
                              .line 68
    005b172a: 0c04                    0043: move-result-object  v4
                              .line 69
    005b172c: 6e10 dc04 0400          0044: invoke-virtual      {v4}, Landroid/view/Window;->getDecorView()Landroid/view/View; # method@04dc
                              .line 72
    005b1732: 0c04                    0047: move-result-object  v4
                              .line 73
    005b1734: 2200 5325               0048: new-instance        v0, Lb/kn1; # type@2553
                              .line 75
    005b1738: 7020 fe53 3000          004a: invoke-direct       {v0, p0}, Lb/kn1;-><init>(Lcom/badoo/mobile/android/BadooActivity;)V # method@53fe
                              .line 78
    005b173e: 6e20 7404 0400          004d: invoke-virtual      {v4, v0}, Landroid/view/View;->setOnApplyWindowInsetsListener(Landroid/view/View$OnApplyWindowInsetsListener;)V # method@0474
                              .line 81
    005b1744: 1204                    0050: const/4             v4, 0
                              .line 82
    005b1746: 6a04 9c5f               0051: sput-boolean        v4, Lb/qq1;->o:Z # field@5f9c
                              .line 84
    005b174a: 6e10 0ef3 0300          0053: invoke-virtual      {p0}, Lcom/badoo/mobile/ui/b;->getIntent()Landroid/content/Intent; # method@f30e
                              .line 87
    005b1750: 0c04                    0056: move-result-object  v4
                              .line 88
    005b1752: 6e10 bf00 0400          0057: invoke-virtual      {v4}, Landroid/content/Intent;->getData()Landroid/net/Uri; # method@00bf
                              .line 91
    005b1758: 0c00                    005a: move-result-object  v0
                              .line 92
    005b175a: 6e10 c200 0400          005b: invoke-virtual      {v4}, Landroid/content/Intent;->getFlags()I # method@00c2
                              .line 95
    005b1760: 0a01                    005e: move-result         v1
                              .line 96
    005b1762: 1502 4000               005f: const/high16        v2, 0x400000
                              .line 98
    005b1766: b521                    0061: and-int/2addr       v1, v2
                              .line 99
    005b1768: 3801 2000               0062: if-eqz              v1, :cond_0082
                             .line 101
    005b176c: 3900 1e00               0064: if-nez              v0, :cond_0082
                             .line 103
    005b1770: 6e10 c200 0400          0066: invoke-virtual      {v4}, Landroid/content/Intent;->getFlags()I # method@00c2
                             .line 106
    005b1776: 0a00                    0069: move-result         v0
                             .line 107
    005b1778: 1501 0010               006a: const/high16        v1, 0x10000000
                             .line 109
    005b177c: b510                    006c: and-int/2addr       v0, v1
                             .line 110
    005b177e: 3800 0c00               006d: if-eqz              v0, :cond_0079
                             .line 112
    005b1782: 6e10 c200 0400          006f: invoke-virtual      {v4}, Landroid/content/Intent;->getFlags()I # method@00c2
                             .line 115
    005b1788: 0a00                    0072: move-result         v0
                             .line 116
    005b178a: 1401 0080 0000          0073: const               v1, 0x8000
                             .line 119
    005b1790: b510                    0076: and-int/2addr       v0, v1
                             .line 120
    005b1792: 3900 0b00               0077: if-nez              v0, :cond_0082
                             .line 122
                            cond_0079:
    005b1796: 6204 720e               0079: sget-object         v4, Lb/cnp;->a:Lb/cnp$a; # field@0e72
                             .line 124
    005b179a: 6e10 e7fc 0400          007b: invoke-virtual      {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class; # method@fce7
                             .line 127
    005b17a0: 6e10 a9b9 0300          007e: invoke-virtual      {p0}, Lcom/badoo/mobile/android/BadooActivity;->finish()V # method@b9a9
                             .line 130
    005b17a6: 0e00                    0081: return-void         
                             .line 131
                            cond_0082: # 3 refs
    005b17a8: 7110 6077 0300          0082: invoke-static       {p0}, Lb/pt1;->a(Lb/a4h;)V # method@7760
                             .line 134
    005b17ae: 6200 c75c               0085: sget-object         v0, Lb/qi9;->F6:Lb/qi9; # field@5cc7
                             .line 136
    005b17b2: 1201                    0087: const/4             v1, 0
                             .line 137
    005b17b4: 6e20 df7b 1000          0088: invoke-virtual      {v0, v1}, Lb/qi9;->e(Ljava/lang/Object;)I # method@7bdf
                             .line 140
    005b17ba: 6200 ef58               008b: sget-object         v0, Lb/pr0;->o:Lb/ad7; # field@58ef
                             .line 142
    005b17be: 3800 0300               008d: if-eqz              v0, :cond_0090
                             .line 144
    005b17c2: 0701                    008f: move-object         v1, v0
                             .line 145
                            cond_0090:
    005b17c4: 6e10 a509 0100          0090: invoke-virtual      {v1}, Lb/ad7;->X()Lb/plq; # method@09a5
                             .line 148
    005b17ca: 0c00                    0093: move-result-object  v0
                             .line 149
    005b17cc: 7210 fa75 0000          0094: invoke-interface    {v0}, Lb/plq;->f()V # method@75fa
                             .line 152
    005b17d2: 6e20 a8b9 4300          0097: invoke-virtual      {p0, v4}, Lcom/badoo/mobile/android/BadooActivity;->R2(Landroid/content/Intent;)V # method@b9a8
                             .line 206
    005b17d8: 0e00                    009a: return-void         
    
.end method

.method public final R2(Landroid/content/Intent;)V
    .registers 5

                               .line 1
    005b15b8: 1a00 d4b3               0000: const-string        v0, "exit" # string@b3d4
                               .line 3
    005b15bc: 1201                    0002: const/4             v1, 0
                               .line 4
    005b15be: 6e30 ba00 0401          0003: invoke-virtual      {v4, v0, v1}, Landroid/content/Intent;->getBooleanExtra(Ljava/lang/String;, Z)Z # method@00ba
                               .line 7
    005b15c4: 0a00                    0006: move-result         v0
                               .line 8
    005b15c6: 3800 1000               0007: if-eqz              v0, :cond_0017
                              .line 10
    005b15ca: 6e10 a9b9 0300          0009: invoke-virtual      {p0}, Lcom/badoo/mobile/android/BadooActivity;->finish()V # method@b9a9
                              .line 13
    005b15d0: 2204 0e2c               000c: new-instance        v4, Lb/mn1; # type@2c0e
                              .line 15
    005b15d4: 1a00 d913               000e: const-string        v0, "DelayedExit" # string@13d9
                              .line 17
    005b15d8: 7020 51fd 0400          0010: invoke-direct       {v4, v0}, Ljava/lang/Thread;-><init>(Ljava/lang/String;)V # method@fd51
                              .line 20
    005b15de: 6e10 61fd 0400          0013: invoke-virtual      {v4}, Ljava/lang/Thread;->start()V # method@fd61
                              .line 23
    005b15e4: 0e00                    0016: return-void         
                              .line 24
                            cond_0017:
    005b15e6: 6200 8711               0017: sget-object         v0, Lb/d8m;->c:Lb/wld; # field@1187
                              .line 26
    005b15ea: 2201 e020               0019: new-instance        v1, Lb/j91; # type@20e0
                              .line 28
    005b15ee: 1212                    001b: const/4             v2, 0x1
                              .line 29
    005b15f0: 7040 ba4b 2143          001c: invoke-direct       {v1, v2, p0, v4}, Lb/j91;-><init>(I, Ljava/lang/Object;, Ljava/lang/Object;)V # method@4bba
                              .line 32
    005b15f6: 6e20 15a0 1000          001f: invoke-virtual      {v0, v1}, Lb/w7m;->b(Ljava/lang/Runnable;)Lb/ol8; # method@a015
                              .line 35
    005b15fc: 0c04                    0022: move-result-object  v4
                              .line 36
    005b15fe: 5b34 159f               0023: iput-object         v4, p0, Lcom/badoo/mobile/android/BadooActivity;->N:Lb/ol8; # field@9f15
                              .line 79
    005b1602: 0e00                    0025: return-void         
    
.end method

.method public final finish()V
    .registers 2

                               .line 1
    005b159c: 6f10 0df3 0100          0000: invoke-super        {v1}, Lcom/badoo/mobile/ui/b;->finish()V # method@f30d
                               .line 4
    005b15a2: 6200 d287               0003: sget-object         v0, Lb/yq1;->a:[Lb/yq1; # field@87d2
                              .line 17
    005b15a6: 0e00                    0005: return-void         
    
.end method

.method public final h1()V
    .registers 3

                               .line 1
    005b1614: 2200 bc2d               0000: new-instance        v0, Lb/n61; # type@2dbc
                               .line 3
    005b1618: 1211                    0002: const/4             v1, 0x1
                               .line 4
    005b161a: 7030 dc64 2001          0003: invoke-direct       {v0, v2, v1}, Lb/n61;-><init>(Ljava/lang/Object;, I)V # method@64dc
                               .line 7
    005b1620: 6e20 5000 0200          0006: invoke-virtual      {v2, v0}, Landroid/app/Activity;->runOnUiThread(Ljava/lang/Runnable;)V # method@0050
                              .line 17
    005b1626: 0e00                    0009: return-void         
    
.end method

.method public final l2()Z
    .registers 2

                               .line 1
    005b150c: 1200                    0000: const/4             v0, 0
    005b150e: 0f00                    0001: return              v0
    
.end method

.method public final onDestroy()V
    .registers 4

                               .line 1
    005b17ec: 6f10 17f3 0300          0000: invoke-super        {v3}, Lcom/badoo/mobile/ui/b;->onDestroy()V # method@f317
                               .line 4
    005b17f2: 6200 ef58               0003: sget-object         v0, Lb/pr0;->o:Lb/ad7; # field@58ef
                               .line 6
    005b17f6: 1201                    0005: const/4             v1, 0
                               .line 7
    005b17f8: 3800 0300               0006: if-eqz              v0, :cond_0009
                               .line 9
    005b17fc: 2802                    0008: goto                :goto_000a
                              .line 10
                            cond_0009:
    005b17fe: 0710                    0009: move-object         v0, v1
                              .line 11
                            goto_000a:
    005b1800: 6e10 9209 0000          000a: invoke-virtual      {v0}, Lb/ad7;->E()Lb/fy0; # method@0992
                              .line 14
    005b1806: 0c00                    000d: move-result-object  v0
                              .line 15
    005b1808: 7210 a330 0000          000e: invoke-interface    {v0}, Lb/fy0;->b()V # method@30a3
                              .line 18
    005b180e: 5430 149f               0011: iget-object         v0, v3, Lcom/badoo/mobile/android/BadooActivity;->K:Lb/j4e; # field@9f14
                              .line 20
    005b1812: 7210 594b 0000          0013: invoke-interface    {v0}, Lb/j4e;->isInitialized()Z # method@4b59
                              .line 23
    005b1818: 0a02                    0016: move-result         v2
                              .line 24
    005b181a: 3802 1500               0017: if-eqz              v2, :cond_002c
                              .line 26
    005b181e: 7210 584b 0000          0019: invoke-interface    {v0}, Lb/j4e;->getValue()Ljava/lang/Object; # method@4b58
                              .line 29
    005b1824: 0c00                    001c: move-result-object  v0
                              .line 30
    005b1826: 1f00 7e1d               001d: check-cast          v0, Lb/i2e; # type@1d7e
                              .line 32
    005b182a: 6e10 e7fc 0000          001f: invoke-virtual      {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class; # method@fce7
                              .line 35
    005b1830: 6202 8f5d               0022: sget-object         v2, Lb/qi9;->b0:Lb/qi9; # field@5d8f
                              .line 37
    005b1834: 6e20 e27b 0200          0024: invoke-virtual      {v2, v0}, Lb/qi9;->h(Lb/kh2;)V # method@7be2
                              .line 40
    005b183a: 6202 995d               0027: sget-object         v2, Lb/qi9;->c0:Lb/qi9; # field@5d99
                              .line 42
    005b183e: 6e20 e27b 0200          0029: invoke-virtual      {v2, v0}, Lb/qi9;->h(Lb/kh2;)V # method@7be2
                              .line 45
                            cond_002c:
    005b1844: 5430 159f               002c: iget-object         v0, v3, Lcom/badoo/mobile/android/BadooActivity;->N:Lb/ol8; # field@9f15
                              .line 47
    005b1848: 3800 0500               002e: if-eqz              v0, :cond_0033
                              .line 49
    005b184c: 7210 086f 0000          0030: invoke-interface    {v0}, Lb/ol8;->dispose()V # method@6f08
                              .line 52
                            cond_0033:
    005b1852: 5b31 159f               0033: iput-object         v1, v3, Lcom/badoo/mobile/android/BadooActivity;->N:Lb/ol8; # field@9f15
                              .line 61
    005b1856: 0e00                    0035: return-void         
    
.end method

.method public final onNewIntent(Landroid/content/Intent;)V
    .registers 4

                               .line 1
    005b1868: 6200 720e               0000: sget-object         v0, Lb/cnp;->a:Lb/cnp$a; # field@0e72
                               .line 3
    005b186c: 6e10 e7fc 0000          0002: invoke-virtual      {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class; # method@fce7
                               .line 6
    005b1872: 6201 189f               0005: sget-object         v1, Lcom/badoo/mobile/android/BadooActivity;->Q:Lb/j4e; # field@9f18
                               .line 8
    005b1876: 7210 584b 0100          0007: invoke-interface    {v1}, Lb/j4e;->getValue()Ljava/lang/Object; # method@4b58
                              .line 11
    005b187c: 0c01                    000a: move-result-object  v1
                              .line 12
    005b187e: 1f01 8e6f               000b: check-cast          v1, Ljava/lang/String; # type@6f8e
                              .line 14
    005b1882: 6e10 e7fc 0000          000d: invoke-virtual      {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class; # method@fce7
                              .line 17
    005b1888: 6f20 18f3 3200          0010: invoke-super        {p0, v3}, Lcom/badoo/mobile/ui/b;->onNewIntent(Landroid/content/Intent;)V # method@f318
                              .line 20
    005b188e: 6e10 4a00 0200          0013: invoke-virtual      {p0}, Landroid/app/Activity;->isTaskRoot()Z # method@004a
                              .line 23
    005b1894: 0a00                    0016: move-result         v0
                              .line 24
    005b1896: 3800 0500               0017: if-eqz              v0, :cond_001c
                              .line 26
    005b189a: 6e20 a8b9 3200          0019: invoke-virtual      {p0, v3}, Lcom/badoo/mobile/android/BadooActivity;->R2(Landroid/content/Intent;)V # method@b9a8
                              .line 79
                            cond_001c:
    005b18a0: 0e00                    001c: return-void         
    
.end method

.method public final s(Ljava/lang/String;)V
    .registers 4

                               .line 1
    005b18b4: 2200 2e1f               0000: new-instance        v0, Lb/in1; # type@1f2e
                               .line 3
    005b18b8: 1201                    0002: const/4             v1, 0
                               .line 4
    005b18ba: 7040 2548 1032          0003: invoke-direct       {v0, v1, p0, v3}, Lb/in1;-><init>(I, Ljava/lang/Object;, Ljava/lang/Object;)V # method@4825
                               .line 7
    005b18c0: 6e20 5000 0200          0006: invoke-virtual      {p0, v0}, Landroid/app/Activity;->runOnUiThread(Ljava/lang/Runnable;)V # method@0050
                              .line 27
    005b18c6: 0e00                    0009: return-void         
    
.end method