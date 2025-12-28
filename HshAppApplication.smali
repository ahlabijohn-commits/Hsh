.class public Lcom/hsh/me/hshAppApplication;
.super Lb/x12;
.source "SourceFile"


# static fields
.field public static final s:Z


# instance fields
.field public p:Lb/nn8;

.field public final q:Lb/nc7;

.field public final r:Ljava/util/concurrent/atomic/AtomicBoolean;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x1c

    .line 4
    .line 5
    if-lt v0, v1, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    const/4 v0, 0x0

    .line 10
    :goto_0
    sput-boolean v0, Lcom/hsh/me/hshAppApplication;->s:Z

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>()V
    .locals 3

    .line 1
    new-instance v0, Lb/nc7;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, v1}, Lb/nc7;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0}, Lb/x12;-><init>()V

    .line 8
    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    iput-object v1, p0, Lcom/hsh/me/hshAppApplication;->p:Lb/nn8;

    .line 12
    .line 13
    new-instance v1, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 14
    .line 15
    const/4 v2, 0x0

    .line 16
    invoke-direct {v1, v2}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 17
    .line 18
    .line 19
    iput-object v1, p0, Lcom/hsh/me/hshAppApplication;->r:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 20
    .line 21
    iput-object v0, p0, Lcom/hsh/me/hshAppApplication;->q:Lb/nc7;

    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final a()Z
    .locals 1

    .line 1
    sget-boolean v0, Lcom/hsh/me/hshAppApplication;->s:Z

    .line 2
    .line 3
    return v0
.end method

.method public final attachBaseContext(Landroid/content/Context;)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Landroid/content/ContextWrapper;->attachBaseContext(Landroid/content/Context;)V

    .line 2
    .line 3
    .line 4
    const/4 p1, 0x0

    .line 5
    invoke-static {p0, p1}, Lb/otr;->c(Landroid/content/Context;Z)Z

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final b()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/hsh/me/hshAppApplication;->r:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    return v0
.end method

.method public final c()V
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/hsh/me/hshAppApplication;->r:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->getAndSet(Z)Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    sget-object v0, Lb/ema;->h:Lb/on8;

    .line 12
    .line 13
    invoke-virtual {v0}, Lb/on8;->a()Lb/w3g;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sget-object v1, Lb/kxs;->a:Lb/jxs;

    .line 18
    .line 19
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 23
    .line 24
    .line 25
    move-result-wide v1

    .line 26
    iget-object v3, p0, Lcom/hsh/me/hshAppApplication;->p:Lb/nn8;

    .line 27
    .line 28
    invoke-interface {v3}, Lb/y12;->o()Lb/ej2;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    invoke-virtual {v3}, Lb/ej2;->a()V

    .line 33
    .line 34
    .line 35
    sget-object v3, Lkotlin/Unit;->a:Lkotlin/Unit;

    .line 36
    .line 37
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 38
    .line 39
    .line 40
    move-result-wide v3

    .line 41
    sub-long/2addr v3, v1

    .line 42
    sget-object v1, Lb/mf0;->R:Lb/mf0;

    .line 43
    .line 44
    invoke-interface {v0, v3, v4, v1}, Lb/w3g;->f(JLb/mf0;)V

    .line 45
    .line 46
    .line 47
    return-void
.end method

.method public final e()V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/hsh/me/hshAppApplication;->p:Lb/nn8;

    .line 2
    .line 3
    iget-object v0, v0, Lb/nn8;->L:Lb/zqn;

    .line 4
    .line 5
    invoke-interface {v0}, Ljavax/inject/Provider;->get()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Lb/jo2;

    .line 10
    .line 11
    invoke-virtual {v0}, Lb/jo2;->a()V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final f()V
    .locals 2

    .line 1
    sget-object v0, Lb/x95;->d:Lb/cwq;

    .line 2
    .line 3
    invoke-static {v0}, Lb/ix0;->a(Lb/cwq;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lb/yco;

    .line 8
    .line 9
    const-string v1, "CLIENT_ERROR"

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Lb/yco;->a(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final h()Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lb/cu9;",
            ">;"
        }
    .end annotation

    .line 1
    invoke-static {}, Lb/f92;->values()[Lb/f92;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    return-object v0
.end method

.method public final i()V
    .locals 1

    .line 1
    const-string v0, "com.hsh.me"

    .line 2
    .line 3
    sput-object v0, Lb/i27;->b:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 6
    .line 7
    .line 8
    const-string v0, "5.445.0"

    .line 9
    .line 10
    sput-object v0, Lb/i27;->a:Ljava/lang/String;

    .line 11
    .line 12
    sget v0, Lcom/hsh/me/R$string;->build_info:I

    .line 13
    .line 14
    invoke-virtual {p0, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    sput-object v0, Lb/i27;->c:Ljava/lang/String;

    .line 19
    .line 20
    const-string v0, "BMA/Android"

    .line 21
    .line 22
    sput-object v0, Lb/i27;->d:Ljava/lang/String;

    .line 23
    .line 24
    sget-object v0, Lb/zw0;->b:Lb/zw0;

    .line 25
    .line 26
    sput-object v0, Lb/i27;->e:Lb/zw0;

    .line 27
    .line 28
    const/4 v0, 0x1

    .line 29
    sput v0, Lb/i27;->g:I

    .line 30
    .line 31
    sget-object v0, Lb/w64;->c:Lb/w64;

    .line 32
    .line 33
    sput-object v0, Lb/i27;->f:Lb/w64;

    .line 34
    .line 35
    return-void
.end method

.method public final j(Lb/hme;Lb/lxo;Lb/ldb;)Lb/fzm;
    .locals 6

    .line 1
    new-instance v0, Lb/fzm;

    .line 2
    .line 3
    sget-object v4, Lb/kxs;->a:Lb/jxs;

    .line 4
    .line 5
    new-instance v5, Lb/hoh;

    .line 6
    .line 7
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    move-object v1, p1

    .line 11
    move-object v2, p2

    .line 12
    move-object v3, p3

    .line 13
    invoke-direct/range {v0 .. v5}, Lb/fzm;-><init>(Lb/hme;Lb/lxo;Lb/ldb;Lb/ixs;Lb/hoh;)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method

.method public final k()I
    .locals 1

    .line 1
    sget v0, Lcom/hsh/me/R$string;->locale_used:I

    .line 2
    .line 3
    return v0
.end method

.method public final l(Lb/ps0;)Lb/zg2;
    .locals 6
    .param p1    # Lb/ps0;
        .annotation build Landroidx/annotation/NonNull;
        .end annotation
    .end param
    .annotation build Landroidx/annotation/NonNull;
    .end annotation

    .line 1
    new-instance v0, Lb/zg2;

    .line 2
    .line 3
    sget-object v1, Lb/na6;->f:Lb/ju8;

    .line 4
    .line 5
    iget-object v1, v1, Lb/ju8;->a:Lb/okg;

    .line 6
    .line 7
    new-instance v2, Lb/iel;

    .line 8
    .line 9
    invoke-interface {v1}, Lb/okg;->getValue()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    check-cast v1, Lb/cpk;

    .line 14
    .line 15
    invoke-direct {v2, v1}, Lb/iel;-><init>(Lb/cpk;)V

    .line 16
    .line 17
    .line 18
    new-instance v1, Lb/s02;

    .line 19
    .line 20
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 21
    .line 22
    .line 23
    new-instance v3, Lb/ah2;

    .line 24
    .line 25
    sget-object v4, Lb/tn;->c:Lb/qn8;

    .line 26
    .line 27
    iget-object v4, v4, Lb/qn8;->g:Lb/eo8;

    .line 28
    .line 29
    iget-object v4, v4, Lb/eo8;->i:Lb/zqn;

    .line 30
    .line 31
    invoke-interface {v4}, Ljavax/inject/Provider;->get()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v4

    .line 35
    check-cast v4, Lb/rfk;

    .line 36
    .line 37
    sget-object v5, Lb/tn;->c:Lb/qn8;

    .line 38
    .line 39
    iget-object v5, v5, Lb/qn8;->g:Lb/eo8;

    .line 40
    .line 41
    iget-object v5, v5, Lb/eo8;->n:Lb/zqn;

    .line 42
    .line 43
    invoke-interface {v5}, Ljavax/inject/Provider;->get()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v5

    .line 47
    check-cast v5, Lb/xtn;

    .line 48
    .line 49
    invoke-direct {v3, v4, v5}, Lb/ah2;-><init>(Lb/rfk;Lb/xtn;)V

    .line 50
    .line 51
    .line 52
    new-instance v4, Lb/t02;

    .line 53
    .line 54
    const/4 v5, 0x0

    .line 55
    invoke-direct {v4, v5}, Lb/t02;-><init>(I)V

    .line 56
    .line 57
    .line 58
    new-instance v5, Lb/yg2;

    .line 59
    .line 60
    invoke-direct {v5, v2, v1, v4}, Lb/yg2;-><init>(Lb/iel;Lb/s02;Lb/t02;)V

    .line 61
    .line 62
    .line 63
    invoke-direct {v0, p1, v5, v3}, Lb/zg2;-><init>(Lb/ps0;Lb/yg2;Lb/ah2;)V

    .line 64
    .line 65
    .line 66
    return-object v0
.end method

.method public final m()Lb/zxr;
    .locals 1
    .annotation build Landroidx/annotation/NonNull;
    .end annotation

    .line 1
    iget-object v0, p0, Lcom/hsh/me/hshAppApplication;->p:Lb/nn8;

    .line 2
    .line 3
    invoke-virtual {v0}, Lb/nn8;->a()Lb/zxr;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    return-object v0
.end method

.method public final n()V
    .locals 1

    .line 1
    const-string v0, "https://m.hsh.com/terms/"

    .line 2
    .line 3
    sput-object v0, Lb/znk;->b:Ljava/lang/String;

    .line 4
    .line 5
    const-string v0, "bd://oauth"

    .line 6
    .line 7
    sput-object v0, Lb/znk;->c:Ljava/lang/String;

    .line 8
    .line 9
    const-string v0, "fb://page/111798952177249"

    .line 10
    .line 11
    sput-object v0, Lb/znk;->e:Ljava/lang/String;

    .line 12
    .line 13
    const-string v0, "https://www.facebook.com/hsh/"

    .line 14
    .line 15
    sput-object v0, Lb/znk;->d:Ljava/lang/String;

    .line 16
    .line 17
    sget-object v0, Lb/w64;->c:Lb/w64;

    .line 18
    .line 19
    sput-object v0, Lb/znk;->f:Lb/w64;

    .line 20
    .line 21
    const-string v0, "ssl://bma.hsh.app:443"

    .line 22
    .line 23
    sput-object v0, Lb/op0;->c:Ljava/lang/String;

    .line 24
    .line 25
    return-void
.end method

.method public final o()V
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    iget-object v0, v1, Lcom/hsh/me/hshAppApplication;->q:Lb/nc7;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    new-instance v2, Lb/nle;

    .line 9
    .line 10
    sget v0, Lcom/hsh/me/R$string;->system_translation_version:I

    .line 11
    .line 12
    invoke-virtual {v1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    const-string v3, "getString(...)"

    .line 17
    .line 18
    invoke-static {v0, v3}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullExpressionValue(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-direct {v2, v0}, Lb/nle;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    new-instance v3, Lb/z92;

    .line 25
    .line 26
    invoke-direct {v3, v1}, Lb/z92;-><init>(Lcom/hsh/me/hshAppApplication;)V

    .line 27
    .line 28
    .line 29
    sget-object v4, Lb/op0;->c:Ljava/lang/String;

    .line 30
    .line 31
    new-instance v5, Lb/c74;

    .line 32
    .line 33
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 34
    .line 35
    .line 36
    new-instance v6, Lb/kjm;

    .line 37
    .line 38
    invoke-direct {v6, v1}, Lb/kjm;-><init>(Lcom/hsh/me/hshAppApplication;)V

    .line 39
    .line 40
    .line 41
    sget-object v0, Lcom/hsh/me/a$a;->a:Lcom/hsh/me/a$a;

    .line 42
    .line 43
    const-string v7, "getNetworkConfiguration(...)"

    .line 44
    .line 45
    invoke-static {v0, v7}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullExpressionValue(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    new-instance v0, Lb/on8;

    .line 49
    .line 50
    invoke-direct/range {v0 .. v6}, Lb/on8;-><init>(Lcom/hsh/me/hshAppApplication;Lb/nle;Lb/z92;Ljava/lang/String;Lb/c74;Lb/kjm;)V

    .line 51
    .line 52
    .line 53
    move-object v7, v0

    .line 54
    sput-object v7, Lb/ema;->h:Lb/on8;

    .line 55
    .line 56
    new-instance v0, Lb/b12;

    .line 57
    .line 58
    const/4 v15, 0x0

    .line 59
    invoke-direct {v0, v15}, Lb/b12;-><init>(I)V

    .line 60
    .line 61
    .line 62
    invoke-static {v0}, Lb/umg;->b(Lkotlin/jvm/functions/Function0;)Lb/okg;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    sput-object v0, Lb/qv0;->k:Lb/okg;

    .line 67
    .line 68
    new-instance v8, Lb/uo8;

    .line 69
    .line 70
    invoke-direct {v8, v1, v7}, Lb/uo8;-><init>(Lcom/hsh/me/hshAppApplication;Lb/on8;)V

    .line 71
    .line 72
    .line 73
    new-instance v0, Lb/jc;

    .line 74
    .line 75
    const/4 v9, 0x2

    .line 76
    invoke-direct {v0, v7, v9}, Lb/jc;-><init>(Ljava/lang/Object;I)V

    .line 77
    .line 78
    .line 79
    invoke-static {v0}, Lb/umg;->b(Lkotlin/jvm/functions/Function0;)Lb/okg;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    new-instance v10, Lb/eo8;

    .line 84
    .line 85
    invoke-direct {v10}, Ljava/lang/Object;-><init>()V

    .line 86
    .line 87
    .line 88
    invoke-static {v0}, Lb/pif;->a(Ljava/lang/Object;)Lb/pif;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    new-instance v2, Lb/lv2;

    .line 93
    .line 94
    invoke-direct {v2, v0}, Lb/lv2;-><init>(Lb/pif;)V

    .line 95
    .line 96
    .line 97
    invoke-static {v2}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    iput-object v0, v10, Lb/eo8;->a:Lb/zqn;

    .line 102
    .line 103
    new-instance v2, Lb/ce2;

    .line 104
    .line 105
    const/4 v11, 0x1

    .line 106
    invoke-direct {v2, v0, v11}, Lb/ce2;-><init>(Lb/zqn;I)V

    .line 107
    .line 108
    .line 109
    invoke-static {v2}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    iput-object v0, v10, Lb/eo8;->b:Lb/zqn;

    .line 114
    .line 115
    iget-object v0, v10, Lb/eo8;->a:Lb/zqn;

    .line 116
    .line 117
    new-instance v2, Lb/oe2;

    .line 118
    .line 119
    invoke-direct {v2, v0, v11}, Lb/oe2;-><init>(Lb/zqn;I)V

    .line 120
    .line 121
    .line 122
    invoke-static {v2}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 123
    .line 124
    .line 125
    move-result-object v0

    .line 126
    iput-object v0, v10, Lb/eo8;->c:Lb/zqn;

    .line 127
    .line 128
    iget-object v0, v10, Lb/eo8;->a:Lb/zqn;

    .line 129
    .line 130
    new-instance v2, Lb/m52;

    .line 131
    .line 132
    invoke-direct {v2, v0, v11}, Lb/m52;-><init>(Lb/zqn;I)V

    .line 133
    .line 134
    .line 135
    invoke-static {v2}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 136
    .line 137
    .line 138
    move-result-object v0

    .line 139
    iput-object v0, v10, Lb/eo8;->d:Lb/zqn;

    .line 140
    .line 141
    iget-object v0, v10, Lb/eo8;->a:Lb/zqn;

    .line 142
    .line 143
    new-instance v2, Lb/c52;

    .line 144
    .line 145
    invoke-direct {v2, v0, v11}, Lb/c52;-><init>(Lb/zqn;I)V

    .line 146
    .line 147
    .line 148
    invoke-static {v2}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    iput-object v0, v10, Lb/eo8;->e:Lb/zqn;

    .line 153
    .line 154
    iget-object v0, v10, Lb/eo8;->a:Lb/zqn;

    .line 155
    .line 156
    new-instance v2, Lb/lh1;

    .line 157
    .line 158
    invoke-direct {v2, v0, v11}, Lb/lh1;-><init>(Lb/zqn;I)V

    .line 159
    .line 160
    .line 161
    invoke-static {v2}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 162
    .line 163
    .line 164
    move-result-object v0

    .line 165
    iput-object v0, v10, Lb/eo8;->f:Lb/zqn;

    .line 166
    .line 167
    iget-object v0, v10, Lb/eo8;->a:Lb/zqn;

    .line 168
    .line 169
    new-instance v2, Lb/jv2;

    .line 170
    .line 171
    invoke-direct {v2, v0, v15}, Lb/jv2;-><init>(Lb/zqn;I)V

    .line 172
    .line 173
    .line 174
    invoke-static {v2}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 175
    .line 176
    .line 177
    move-result-object v0

    .line 178
    iput-object v0, v10, Lb/eo8;->g:Lb/zqn;

    .line 179
    .line 180
    iget-object v0, v10, Lb/eo8;->a:Lb/zqn;

    .line 181
    .line 182
    new-instance v2, Lb/ke2;

    .line 183
    .line 184
    invoke-direct {v2, v0, v11}, Lb/ke2;-><init>(Lb/zqn;I)V

    .line 185
    .line 186
    .line 187
    invoke-static {v2}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 188
    .line 189
    .line 190
    move-result-object v0

    .line 191
    iput-object v0, v10, Lb/eo8;->h:Lb/zqn;

    .line 192
    .line 193
    iget-object v0, v10, Lb/eo8;->a:Lb/zqn;

    .line 194
    .line 195
    new-instance v2, Lb/he2;

    .line 196
    .line 197
    invoke-direct {v2, v0, v11}, Lb/he2;-><init>(Lb/zqn;I)V

    .line 198
    .line 199
    .line 200
    invoke-static {v2}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 201
    .line 202
    .line 203
    move-result-object v0

    .line 204
    iput-object v0, v10, Lb/eo8;->i:Lb/zqn;

    .line 205
    .line 206
    iget-object v0, v10, Lb/eo8;->a:Lb/zqn;

    .line 207
    .line 208
    new-instance v2, Lb/kv2;

    .line 209
    .line 210
    invoke-direct {v2, v0, v15}, Lb/kv2;-><init>(Lb/zqn;I)V

    .line 211
    .line 212
    .line 213
    invoke-static {v2}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 214
    .line 215
    .line 216
    move-result-object v0

    .line 217
    iput-object v0, v10, Lb/eo8;->j:Lb/zqn;

    .line 218
    .line 219
    iget-object v0, v10, Lb/eo8;->a:Lb/zqn;

    .line 220
    .line 221
    new-instance v2, Lb/d52;

    .line 222
    .line 223
    invoke-direct {v2, v0, v11}, Lb/d52;-><init>(Lb/zqn;I)V

    .line 224
    .line 225
    .line 226
    invoke-static {v2}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 227
    .line 228
    .line 229
    move-result-object v0

    .line 230
    iput-object v0, v10, Lb/eo8;->k:Lb/zqn;

    .line 231
    .line 232
    iget-object v0, v10, Lb/eo8;->a:Lb/zqn;

    .line 233
    .line 234
    new-instance v2, Lb/je2;

    .line 235
    .line 236
    invoke-direct {v2, v0, v11}, Lb/je2;-><init>(Lb/zqn;I)V

    .line 237
    .line 238
    .line 239
    invoke-static {v2}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 240
    .line 241
    .line 242
    move-result-object v0

    .line 243
    iput-object v0, v10, Lb/eo8;->l:Lb/zqn;

    .line 244
    .line 245
    iget-object v0, v10, Lb/eo8;->a:Lb/zqn;

    .line 246
    .line 247
    new-instance v2, Lb/mh1;

    .line 248
    .line 249
    invoke-direct {v2, v0, v11}, Lb/mh1;-><init>(Lb/zqn;I)V

    .line 250
    .line 251
    .line 252
    invoke-static {v2}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 253
    .line 254
    .line 255
    move-result-object v0

    .line 256
    iput-object v0, v10, Lb/eo8;->m:Lb/zqn;

    .line 257
    .line 258
    iget-object v0, v10, Lb/eo8;->a:Lb/zqn;

    .line 259
    .line 260
    new-instance v2, Lb/le2;

    .line 261
    .line 262
    invoke-direct {v2, v0, v11}, Lb/le2;-><init>(Lb/zqn;I)V

    .line 263
    .line 264
    .line 265
    invoke-static {v2}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 266
    .line 267
    .line 268
    move-result-object v0

    .line 269
    iput-object v0, v10, Lb/eo8;->n:Lb/zqn;

    .line 270
    .line 271
    iget-object v0, v10, Lb/eo8;->a:Lb/zqn;

    .line 272
    .line 273
    new-instance v2, Lb/me2;

    .line 274
    .line 275
    invoke-direct {v2, v0, v11}, Lb/me2;-><init>(Lb/zqn;I)V

    .line 276
    .line 277
    .line 278
    invoke-static {v2}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 279
    .line 280
    .line 281
    move-result-object v0

    .line 282
    iput-object v0, v10, Lb/eo8;->o:Lb/zqn;

    .line 283
    .line 284
    iget-object v0, v10, Lb/eo8;->a:Lb/zqn;

    .line 285
    .line 286
    new-instance v2, Lb/d62;

    .line 287
    .line 288
    invoke-direct {v2, v0, v11}, Lb/d62;-><init>(Lb/zqn;I)V

    .line 289
    .line 290
    .line 291
    invoke-static {v2}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 292
    .line 293
    .line 294
    move-result-object v0

    .line 295
    iput-object v0, v10, Lb/eo8;->p:Lb/zqn;

    .line 296
    .line 297
    iget-object v0, v10, Lb/eo8;->a:Lb/zqn;

    .line 298
    .line 299
    new-instance v2, Lb/u0;

    .line 300
    .line 301
    invoke-direct {v2, v0, v9}, Lb/u0;-><init>(Lb/zqn;I)V

    .line 302
    .line 303
    .line 304
    invoke-static {v2}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 305
    .line 306
    .line 307
    move-result-object v0

    .line 308
    iput-object v0, v10, Lb/eo8;->q:Lb/zqn;

    .line 309
    .line 310
    sget v0, Lb/vwq;->c:I

    .line 311
    .line 312
    new-instance v0, Ljava/util/ArrayList;

    .line 313
    .line 314
    const/16 v2, 0x10

    .line 315
    .line 316
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 317
    .line 318
    .line 319
    sget-object v2, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 320
    .line 321
    iget-object v3, v10, Lb/eo8;->b:Lb/zqn;

    .line 322
    .line 323
    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 324
    .line 325
    .line 326
    iget-object v3, v10, Lb/eo8;->c:Lb/zqn;

    .line 327
    .line 328
    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 329
    .line 330
    .line 331
    iget-object v3, v10, Lb/eo8;->d:Lb/zqn;

    .line 332
    .line 333
    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 334
    .line 335
    .line 336
    iget-object v3, v10, Lb/eo8;->e:Lb/zqn;

    .line 337
    .line 338
    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 339
    .line 340
    .line 341
    iget-object v3, v10, Lb/eo8;->f:Lb/zqn;

    .line 342
    .line 343
    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 344
    .line 345
    .line 346
    iget-object v3, v10, Lb/eo8;->g:Lb/zqn;

    .line 347
    .line 348
    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 349
    .line 350
    .line 351
    iget-object v3, v10, Lb/eo8;->h:Lb/zqn;

    .line 352
    .line 353
    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 354
    .line 355
    .line 356
    iget-object v3, v10, Lb/eo8;->i:Lb/zqn;

    .line 357
    .line 358
    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 359
    .line 360
    .line 361
    iget-object v3, v10, Lb/eo8;->j:Lb/zqn;

    .line 362
    .line 363
    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 364
    .line 365
    .line 366
    iget-object v3, v10, Lb/eo8;->k:Lb/zqn;

    .line 367
    .line 368
    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 369
    .line 370
    .line 371
    iget-object v3, v10, Lb/eo8;->l:Lb/zqn;

    .line 372
    .line 373
    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 374
    .line 375
    .line 376
    iget-object v3, v10, Lb/eo8;->m:Lb/zqn;

    .line 377
    .line 378
    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 379
    .line 380
    .line 381
    iget-object v3, v10, Lb/eo8;->n:Lb/zqn;

    .line 382
    .line 383
    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 384
    .line 385
    .line 386
    iget-object v3, v10, Lb/eo8;->o:Lb/zqn;

    .line 387
    .line 388
    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 389
    .line 390
    .line 391
    iget-object v3, v10, Lb/eo8;->p:Lb/zqn;

    .line 392
    .line 393
    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 394
    .line 395
    .line 396
    iget-object v3, v10, Lb/eo8;->q:Lb/zqn;

    .line 397
    .line 398
    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 399
    .line 400
    .line 401
    new-instance v3, Lb/vwq;

    .line 402
    .line 403
    invoke-direct {v3, v0, v2}, Lb/vwq;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 404
    .line 405
    .line 406
    new-instance v0, Lb/iv2;

    .line 407
    .line 408
    invoke-direct {v0, v3, v15}, Lb/iv2;-><init>(Lb/zqn;I)V

    .line 409
    .line 410
    .line 411
    invoke-static {v0}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 412
    .line 413
    .line 414
    move-result-object v0

    .line 415
    iput-object v0, v10, Lb/eo8;->r:Lb/zqn;

    .line 416
    .line 417
    iget-object v0, v10, Lb/eo8;->a:Lb/zqn;

    .line 418
    .line 419
    new-instance v2, Lb/k52;

    .line 420
    .line 421
    invoke-direct {v2, v0, v11}, Lb/k52;-><init>(Lb/zqn;I)V

    .line 422
    .line 423
    .line 424
    invoke-static {v2}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 425
    .line 426
    .line 427
    move-result-object v0

    .line 428
    iput-object v0, v10, Lb/eo8;->s:Lb/zqn;

    .line 429
    .line 430
    new-instance v12, Lb/mn8;

    .line 431
    .line 432
    invoke-direct {v12, v7}, Lb/mn8;-><init>(Lb/on8;)V

    .line 433
    .line 434
    .line 435
    invoke-virtual {v7}, Lb/on8;->d()Lb/mgp;

    .line 436
    .line 437
    .line 438
    move-result-object v0

    .line 439
    invoke-virtual {v7}, Lb/on8;->h()Lb/hb7;

    .line 440
    .line 441
    .line 442
    move-result-object v2

    .line 443
    new-instance v3, Lb/twm;

    .line 444
    .line 445
    sget-object v4, Lb/lw2;->l:Lb/lw2;

    .line 446
    .line 447
    sget-object v5, Lb/lw2;->d:Lb/lw2;

    .line 448
    .line 449
    sget-object v6, Lb/lw2;->m:Lb/lw2;

    .line 450
    .line 451
    filled-new-array {v6, v4, v5}, [Lb/lw2;

    .line 452
    .line 453
    .line 454
    move-result-object v4

    .line 455
    invoke-static {v4}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 456
    .line 457
    .line 458
    move-result-object v4

    .line 459
    invoke-direct {v3, v4}, Lb/twm;-><init>(Ljava/util/List;)V

    .line 460
    .line 461
    .line 462
    new-instance v4, Lb/rxm;

    .line 463
    .line 464
    sget-object v5, Lb/tcl;->u:Lb/tcl;

    .line 465
    .line 466
    invoke-static {v5}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 467
    .line 468
    .line 469
    move-result-object v5

    .line 470
    invoke-direct {v4, v5}, Lb/rxm;-><init>(Ljava/util/List;)V

    .line 471
    .line 472
    .line 473
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 474
    .line 475
    .line 476
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 477
    .line 478
    .line 479
    new-instance v6, Lb/fo8;

    .line 480
    .line 481
    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    .line 482
    .line 483
    .line 484
    invoke-static {v0}, Lb/pif;->a(Ljava/lang/Object;)Lb/pif;

    .line 485
    .line 486
    .line 487
    move-result-object v0

    .line 488
    iput-object v0, v6, Lb/fo8;->a:Lb/pif;

    .line 489
    .line 490
    invoke-static {v2}, Lb/pif;->a(Ljava/lang/Object;)Lb/pif;

    .line 491
    .line 492
    .line 493
    move-result-object v0

    .line 494
    iput-object v0, v6, Lb/fo8;->b:Lb/pif;

    .line 495
    .line 496
    iget-object v2, v6, Lb/fo8;->a:Lb/pif;

    .line 497
    .line 498
    new-instance v5, Lb/qd8;

    .line 499
    .line 500
    invoke-direct {v5, v2, v0, v15}, Lb/qd8;-><init>(Lb/zqn;Lb/zqn;I)V

    .line 501
    .line 502
    .line 503
    invoke-static {v5}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 504
    .line 505
    .line 506
    move-result-object v0

    .line 507
    iput-object v0, v6, Lb/fo8;->c:Lb/zqn;

    .line 508
    .line 509
    invoke-static {v3}, Lb/pif;->a(Ljava/lang/Object;)Lb/pif;

    .line 510
    .line 511
    .line 512
    move-result-object v0

    .line 513
    iget-object v2, v6, Lb/fo8;->a:Lb/pif;

    .line 514
    .line 515
    iget-object v3, v6, Lb/fo8;->b:Lb/pif;

    .line 516
    .line 517
    new-instance v5, Lb/rd8;

    .line 518
    .line 519
    invoke-direct {v5, v2, v3, v0}, Lb/rd8;-><init>(Lb/pif;Lb/pif;Lb/pif;)V

    .line 520
    .line 521
    .line 522
    invoke-static {v5}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 523
    .line 524
    .line 525
    move-result-object v0

    .line 526
    iput-object v0, v6, Lb/fo8;->d:Lb/zqn;

    .line 527
    .line 528
    invoke-static {v4}, Lb/pif;->a(Ljava/lang/Object;)Lb/pif;

    .line 529
    .line 530
    .line 531
    move-result-object v0

    .line 532
    iget-object v2, v6, Lb/fo8;->a:Lb/pif;

    .line 533
    .line 534
    new-instance v3, Lb/f74;

    .line 535
    .line 536
    invoke-direct {v3, v2, v0, v9}, Lb/f74;-><init>(Lb/zqn;Lb/zqn;I)V

    .line 537
    .line 538
    .line 539
    invoke-static {v3}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 540
    .line 541
    .line 542
    move-result-object v0

    .line 543
    iput-object v0, v6, Lb/fo8;->e:Lb/zqn;

    .line 544
    .line 545
    new-instance v2, Lb/dob;

    .line 546
    .line 547
    new-instance v0, Lb/pal;

    .line 548
    .line 549
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 550
    .line 551
    .line 552
    new-instance v3, Lb/jl2;

    .line 553
    .line 554
    invoke-direct {v3, v9}, Lb/jl2;-><init>(I)V

    .line 555
    .line 556
    .line 557
    invoke-direct {v2, v0, v3}, Lb/dob;-><init>(Lb/pal;Lb/jl2;)V

    .line 558
    .line 559
    .line 560
    new-instance v3, Lb/te3;

    .line 561
    .line 562
    new-instance v0, Lb/k22;

    .line 563
    .line 564
    invoke-direct {v0, v15}, Lb/k22;-><init>(I)V

    .line 565
    .line 566
    .line 567
    new-instance v4, Lb/k22;

    .line 568
    .line 569
    const/4 v5, 0x6

    .line 570
    invoke-direct {v4, v5}, Lb/k22;-><init>(I)V

    .line 571
    .line 572
    .line 573
    new-instance v5, Lb/ula;

    .line 574
    .line 575
    sget-object v13, Lb/xks;->a:Lb/xks;

    .line 576
    .line 577
    invoke-direct {v5, v13}, Lb/ula;-><init>(Ljava/lang/Object;)V

    .line 578
    .line 579
    .line 580
    invoke-direct {v3, v0, v4, v5}, Lb/te3;-><init>(Lb/k22;Lb/k22;Lb/ula;)V

    .line 581
    .line 582
    .line 583
    invoke-virtual {v7}, Lb/on8;->d()Lb/mgp;

    .line 584
    .line 585
    .line 586
    move-result-object v4

    .line 587
    invoke-virtual {v7}, Lb/on8;->h()Lb/hb7;

    .line 588
    .line 589
    .line 590
    move-result-object v5

    .line 591
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 592
    .line 593
    .line 594
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 595
    .line 596
    .line 597
    new-instance v0, Lb/iu8;

    .line 598
    .line 599
    invoke-direct/range {v0 .. v6}, Lb/iu8;-><init>(Lcom/hsh/me/hshAppApplication;Lb/dob;Lb/te3;Lb/mgp;Lb/hb7;Lb/fo8;)V

    .line 600
    .line 601
    .line 602
    new-instance v2, Lb/i22;

    .line 603
    .line 604
    invoke-direct {v2, v15}, Lb/i22;-><init>(I)V

    .line 605
    .line 606
    .line 607
    invoke-static {v2}, Lb/umg;->b(Lkotlin/jvm/functions/Function0;)Lb/okg;

    .line 608
    .line 609
    .line 610
    move-result-object v2

    .line 611
    invoke-virtual {v7}, Lb/on8;->d()Lb/mgp;

    .line 612
    .line 613
    .line 614
    move-result-object v3

    .line 615
    invoke-static {v1}, Lb/xhg;->a(Landroid/content/Context;)Lb/yhg;

    .line 616
    .line 617
    .line 618
    move-result-object v4

    .line 619
    invoke-virtual {v7}, Lb/on8;->w()Lb/qnj;

    .line 620
    .line 621
    .line 622
    move-result-object v5

    .line 623
    invoke-virtual {v7}, Lb/on8;->y()Lb/xi8;

    .line 624
    .line 625
    .line 626
    move-result-object v13

    .line 627
    new-instance v14, Lb/j22;

    .line 628
    .line 629
    invoke-direct {v14, v15}, Lb/j22;-><init>(I)V

    .line 630
    .line 631
    .line 632
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 633
    .line 634
    .line 635
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 636
    .line 637
    .line 638
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 639
    .line 640
    .line 641
    new-instance v15, Lb/rs8;

    .line 642
    .line 643
    invoke-direct {v15}, Ljava/lang/Object;-><init>()V

    .line 644
    .line 645
    .line 646
    invoke-static {v4}, Lb/pif;->a(Ljava/lang/Object;)Lb/pif;

    .line 647
    .line 648
    .line 649
    move-result-object v4

    .line 650
    iput-object v4, v15, Lb/rs8;->a:Lb/pif;

    .line 651
    .line 652
    invoke-static {v5}, Lb/pif;->a(Ljava/lang/Object;)Lb/pif;

    .line 653
    .line 654
    .line 655
    move-result-object v4

    .line 656
    iput-object v4, v15, Lb/rs8;->b:Lb/pif;

    .line 657
    .line 658
    const-string v4, "bd://oauth"

    .line 659
    .line 660
    invoke-static {v4}, Lb/pif;->a(Ljava/lang/Object;)Lb/pif;

    .line 661
    .line 662
    .line 663
    move-result-object v4

    .line 664
    iget-object v5, v15, Lb/rs8;->a:Lb/pif;

    .line 665
    .line 666
    iget-object v9, v15, Lb/rs8;->b:Lb/pif;

    .line 667
    .line 668
    new-instance v11, Lb/dfg;

    .line 669
    .line 670
    invoke-direct {v11, v5, v9, v4}, Lb/dfg;-><init>(Lb/pif;Lb/pif;Lb/pif;)V

    .line 671
    .line 672
    .line 673
    invoke-static {v11}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 674
    .line 675
    .line 676
    move-result-object v4

    .line 677
    iput-object v4, v15, Lb/rs8;->c:Lb/zqn;

    .line 678
    .line 679
    invoke-static {v1}, Lb/pif;->a(Ljava/lang/Object;)Lb/pif;

    .line 680
    .line 681
    .line 682
    move-result-object v4

    .line 683
    iput-object v4, v15, Lb/rs8;->d:Lb/pif;

    .line 684
    .line 685
    invoke-static {v13}, Lb/pif;->a(Ljava/lang/Object;)Lb/pif;

    .line 686
    .line 687
    .line 688
    move-result-object v4

    .line 689
    iput-object v4, v15, Lb/rs8;->e:Lb/pif;

    .line 690
    .line 691
    invoke-static {v14}, Lb/pif;->a(Ljava/lang/Object;)Lb/pif;

    .line 692
    .line 693
    .line 694
    move-result-object v4

    .line 695
    iget-object v5, v15, Lb/rs8;->d:Lb/pif;

    .line 696
    .line 697
    iget-object v9, v15, Lb/rs8;->e:Lb/pif;

    .line 698
    .line 699
    new-instance v11, Lb/xnd;

    .line 700
    .line 701
    const/4 v13, 0x1

    .line 702
    invoke-direct {v11, v5, v9, v4, v13}, Lb/xnd;-><init>(Lb/zqn;Lb/zqn;Lb/cxb;I)V

    .line 703
    .line 704
    .line 705
    invoke-static {v11}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 706
    .line 707
    .line 708
    move-result-object v4

    .line 709
    iput-object v4, v15, Lb/rs8;->f:Lb/zqn;

    .line 710
    .line 711
    invoke-static {v2}, Lb/pif;->a(Ljava/lang/Object;)Lb/pif;

    .line 712
    .line 713
    .line 714
    move-result-object v2

    .line 715
    new-instance v4, Lb/nh2;

    .line 716
    .line 717
    const/4 v5, 0x2

    .line 718
    invoke-direct {v4, v2, v5}, Lb/nh2;-><init>(Lb/zqn;I)V

    .line 719
    .line 720
    .line 721
    invoke-static {v4}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 722
    .line 723
    .line 724
    move-result-object v2

    .line 725
    iput-object v2, v15, Lb/rs8;->g:Lb/zqn;

    .line 726
    .line 727
    invoke-static {v3}, Lb/pif;->a(Ljava/lang/Object;)Lb/pif;

    .line 728
    .line 729
    .line 730
    move-result-object v2

    .line 731
    iget-object v3, v15, Lb/rs8;->g:Lb/zqn;

    .line 732
    .line 733
    new-instance v4, Lb/efg;

    .line 734
    .line 735
    invoke-direct {v4, v2, v3}, Lb/efg;-><init>(Lb/pif;Lb/zqn;)V

    .line 736
    .line 737
    .line 738
    invoke-static {v4}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 739
    .line 740
    .line 741
    move-result-object v2

    .line 742
    iput-object v2, v15, Lb/rs8;->h:Lb/zqn;

    .line 743
    .line 744
    iget-object v3, v15, Lb/rs8;->f:Lb/zqn;

    .line 745
    .line 746
    iget-object v4, v15, Lb/rs8;->c:Lb/zqn;

    .line 747
    .line 748
    new-instance v5, Lb/ffg;

    .line 749
    .line 750
    invoke-direct {v5, v3, v2, v4}, Lb/ffg;-><init>(Lb/zqn;Lb/zqn;Lb/zqn;)V

    .line 751
    .line 752
    .line 753
    invoke-static {v5}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 754
    .line 755
    .line 756
    move-result-object v2

    .line 757
    iput-object v2, v15, Lb/rs8;->i:Lb/zqn;

    .line 758
    .line 759
    sput-object v15, Lb/xp5;->f:Lb/rs8;

    .line 760
    .line 761
    invoke-virtual {v8}, Lb/uo8;->f()Lb/atr;

    .line 762
    .line 763
    .line 764
    move-result-object v2

    .line 765
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 766
    .line 767
    .line 768
    new-instance v9, Lb/sw8;

    .line 769
    .line 770
    invoke-direct {v9}, Ljava/lang/Object;-><init>()V

    .line 771
    .line 772
    .line 773
    invoke-static {v2}, Lb/pif;->a(Ljava/lang/Object;)Lb/pif;

    .line 774
    .line 775
    .line 776
    move-result-object v2

    .line 777
    iput-object v2, v9, Lb/sw8;->a:Lb/pif;

    .line 778
    .line 779
    sget-object v2, Lb/bsr$a;->a:Lb/bsr;

    .line 780
    .line 781
    invoke-static {v2}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 782
    .line 783
    .line 784
    move-result-object v2

    .line 785
    iput-object v2, v9, Lb/sw8;->b:Lb/zqn;

    .line 786
    .line 787
    invoke-static {v1}, Lb/pif;->a(Ljava/lang/Object;)Lb/pif;

    .line 788
    .line 789
    .line 790
    move-result-object v2

    .line 791
    new-instance v3, Lb/jud;

    .line 792
    .line 793
    invoke-direct {v3, v2}, Lb/jud;-><init>(Lb/pif;)V

    .line 794
    .line 795
    .line 796
    invoke-static {v3}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 797
    .line 798
    .line 799
    move-result-object v2

    .line 800
    iput-object v2, v9, Lb/sw8;->c:Lb/zqn;

    .line 801
    .line 802
    iget-object v3, v9, Lb/sw8;->a:Lb/pif;

    .line 803
    .line 804
    iget-object v4, v9, Lb/sw8;->b:Lb/zqn;

    .line 805
    .line 806
    new-instance v5, Lb/xa5;

    .line 807
    .line 808
    invoke-direct {v5, v3, v4, v2}, Lb/xa5;-><init>(Lb/pif;Lb/zqn;Lb/zqn;)V

    .line 809
    .line 810
    .line 811
    invoke-static {v5}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 812
    .line 813
    .line 814
    move-result-object v2

    .line 815
    iput-object v2, v9, Lb/sw8;->d:Lb/zqn;

    .line 816
    .line 817
    iget-object v2, v9, Lb/sw8;->a:Lb/pif;

    .line 818
    .line 819
    iget-object v3, v9, Lb/sw8;->c:Lb/zqn;

    .line 820
    .line 821
    new-instance v4, Lb/asr;

    .line 822
    .line 823
    invoke-direct {v4, v2, v3}, Lb/asr;-><init>(Lb/pif;Lb/zqn;)V

    .line 824
    .line 825
    .line 826
    invoke-static {v4}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 827
    .line 828
    .line 829
    move-result-object v2

    .line 830
    iput-object v2, v9, Lb/sw8;->e:Lb/zqn;

    .line 831
    .line 832
    iget-object v3, v9, Lb/sw8;->d:Lb/zqn;

    .line 833
    .line 834
    new-instance v4, Lb/saj;

    .line 835
    .line 836
    const/4 v13, 0x1

    .line 837
    invoke-direct {v4, v3, v2, v13}, Lb/saj;-><init>(Lb/zqn;Lb/zqn;I)V

    .line 838
    .line 839
    .line 840
    invoke-static {v4}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 841
    .line 842
    .line 843
    move-result-object v2

    .line 844
    iput-object v2, v9, Lb/sw8;->f:Lb/zqn;

    .line 845
    .line 846
    new-instance v2, Lb/fn;

    .line 847
    .line 848
    invoke-direct {v2, v1, v13}, Lb/fn;-><init>(Lcom/hsh/me/hshAppApplication;I)V

    .line 849
    .line 850
    .line 851
    move-object v5, v8

    .line 852
    new-instance v8, Lb/lgj;

    .line 853
    .line 854
    invoke-direct {v8, v2, v15}, Lb/lgj;-><init>(Lb/fn;Lb/rs8;)V

    .line 855
    .line 856
    .line 857
    new-instance v3, Lb/qn8;

    .line 858
    .line 859
    move-object v4, v7

    .line 860
    move-object v2, v10

    .line 861
    move-object v7, v5

    .line 862
    move-object v5, v0

    .line 863
    move-object v0, v3

    .line 864
    move-object v3, v1

    .line 865
    move-object v1, v12

    .line 866
    invoke-direct/range {v0 .. v9}, Lb/qn8;-><init>(Lb/mn8;Lb/eo8;Lcom/hsh/me/hshAppApplication;Lb/on8;Lb/iu8;Lb/fo8;Lb/uo8;Lb/lgj;Lb/sw8;)V

    .line 867
    .line 868
    .line 869
    move-object v3, v0

    .line 870
    move-object v15, v2

    .line 871
    move-object v0, v4

    .line 872
    move-object v4, v5

    .line 873
    move-object v5, v7

    .line 874
    sput-object v3, Lb/tn;->c:Lb/qn8;

    .line 875
    .line 876
    new-instance v7, Lb/d12;

    .line 877
    .line 878
    const/4 v8, 0x0

    .line 879
    invoke-direct {v7, v8}, Lb/d12;-><init>(I)V

    .line 880
    .line 881
    .line 882
    move-object v2, v0

    .line 883
    new-instance v0, Lb/e12;

    .line 884
    .line 885
    move-object v6, v1

    .line 886
    move-object/from16 v1, p0

    .line 887
    .line 888
    invoke-direct/range {v0 .. v6}, Lb/e12;-><init>(Lcom/hsh/me/hshAppApplication;Lb/on8;Lb/qn8;Lb/iu8;Lb/uo8;Lb/mn8;)V

    .line 889
    .line 890
    .line 891
    move-object/from16 v16, v2

    .line 892
    .line 893
    move-object v2, v0

    .line 894
    move-object/from16 v0, v16

    .line 895
    .line 896
    move-object/from16 v16, v5

    .line 897
    .line 898
    new-instance v4, Lb/g12;

    .line 899
    .line 900
    invoke-direct {v4, v7, v1, v2, v8}, Lb/g12;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 901
    .line 902
    .line 903
    invoke-static {v4}, Lb/umg;->b(Lkotlin/jvm/functions/Function0;)Lb/okg;

    .line 904
    .line 905
    .line 906
    move-result-object v2

    .line 907
    sput-object v2, Lb/ep0;->a:Lb/okg;

    .line 908
    .line 909
    invoke-virtual {v0}, Lb/on8;->d()Lb/mgp;

    .line 910
    .line 911
    .line 912
    move-result-object v2

    .line 913
    new-instance v4, Lb/z12;

    .line 914
    .line 915
    invoke-direct {v4, v8}, Lb/z12;-><init>(I)V

    .line 916
    .line 917
    .line 918
    invoke-static {v4}, Lb/umg;->b(Lkotlin/jvm/functions/Function0;)Lb/okg;

    .line 919
    .line 920
    .line 921
    move-result-object v4

    .line 922
    new-instance v5, Lb/h22;

    .line 923
    .line 924
    invoke-direct {v5, v8}, Lb/h22;-><init>(I)V

    .line 925
    .line 926
    .line 927
    invoke-static {v5}, Lb/umg;->b(Lkotlin/jvm/functions/Function0;)Lb/okg;

    .line 928
    .line 929
    .line 930
    move-result-object v5

    .line 931
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 932
    .line 933
    .line 934
    new-instance v6, Lb/ju8;

    .line 935
    .line 936
    invoke-direct {v6, v2, v4, v1, v5}, Lb/ju8;-><init>(Lb/mgp;Lb/okg;Lcom/hsh/me/hshAppApplication;Lb/okg;)V

    .line 937
    .line 938
    .line 939
    sput-object v6, Lb/na6;->f:Lb/ju8;

    .line 940
    .line 941
    new-instance v2, Lb/ov8;

    .line 942
    .line 943
    invoke-direct {v2, v0, v3}, Lb/ov8;-><init>(Lb/on8;Lb/qn8;)V

    .line 944
    .line 945
    .line 946
    sput-object v2, Lb/s0b;->c:Lb/ov8;

    .line 947
    .line 948
    new-instance v2, Lb/l22;

    .line 949
    .line 950
    invoke-direct {v2, v0, v8}, Lb/l22;-><init>(Ljava/lang/Object;I)V

    .line 951
    .line 952
    .line 953
    invoke-static {v2}, Lb/umg;->b(Lkotlin/jvm/functions/Function0;)Lb/okg;

    .line 954
    .line 955
    .line 956
    move-result-object v2

    .line 957
    invoke-virtual {v0}, Lb/on8;->h()Lb/hb7;

    .line 958
    .line 959
    .line 960
    move-result-object v3

    .line 961
    invoke-virtual {v0}, Lb/on8;->d()Lb/mgp;

    .line 962
    .line 963
    .line 964
    move-result-object v4

    .line 965
    invoke-virtual {v0}, Lb/on8;->w()Lb/qnj;

    .line 966
    .line 967
    .line 968
    move-result-object v0

    .line 969
    invoke-static {v1}, Lb/xhg;->a(Landroid/content/Context;)Lb/yhg;

    .line 970
    .line 971
    .line 972
    move-result-object v5

    .line 973
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 974
    .line 975
    .line 976
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 977
    .line 978
    .line 979
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 980
    .line 981
    .line 982
    new-instance v6, Lb/it8;

    .line 983
    .line 984
    new-instance v8, Lb/ep0;

    .line 985
    .line 986
    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    .line 987
    .line 988
    .line 989
    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    .line 990
    .line 991
    .line 992
    invoke-static {v1}, Lb/pif;->a(Ljava/lang/Object;)Lb/pif;

    .line 993
    .line 994
    .line 995
    move-result-object v7

    .line 996
    iput-object v7, v6, Lb/it8;->a:Lb/pif;

    .line 997
    .line 998
    invoke-static {v2}, Lb/pif;->a(Ljava/lang/Object;)Lb/pif;

    .line 999
    .line 1000
    .line 1001
    move-result-object v2

    .line 1002
    iput-object v2, v6, Lb/it8;->b:Lb/pif;

    .line 1003
    .line 1004
    invoke-static {v3}, Lb/pif;->a(Ljava/lang/Object;)Lb/pif;

    .line 1005
    .line 1006
    .line 1007
    move-result-object v2

    .line 1008
    iput-object v2, v6, Lb/it8;->c:Lb/pif;

    .line 1009
    .line 1010
    invoke-static {v4}, Lb/pif;->a(Ljava/lang/Object;)Lb/pif;

    .line 1011
    .line 1012
    .line 1013
    move-result-object v2

    .line 1014
    iput-object v2, v6, Lb/it8;->d:Lb/pif;

    .line 1015
    .line 1016
    invoke-static {v0}, Lb/pif;->a(Ljava/lang/Object;)Lb/pif;

    .line 1017
    .line 1018
    .line 1019
    move-result-object v0

    .line 1020
    iput-object v0, v6, Lb/it8;->e:Lb/pif;

    .line 1021
    .line 1022
    invoke-static {v5}, Lb/pif;->a(Ljava/lang/Object;)Lb/pif;

    .line 1023
    .line 1024
    .line 1025
    move-result-object v14

    .line 1026
    iget-object v9, v6, Lb/it8;->a:Lb/pif;

    .line 1027
    .line 1028
    iget-object v10, v6, Lb/it8;->b:Lb/pif;

    .line 1029
    .line 1030
    iget-object v11, v6, Lb/it8;->c:Lb/pif;

    .line 1031
    .line 1032
    iget-object v12, v6, Lb/it8;->d:Lb/pif;

    .line 1033
    .line 1034
    iget-object v13, v6, Lb/it8;->e:Lb/pif;

    .line 1035
    .line 1036
    new-instance v7, Lb/guh;

    .line 1037
    .line 1038
    invoke-direct/range {v7 .. v14}, Lb/guh;-><init>(Lb/ep0;Lb/pif;Lb/pif;Lb/pif;Lb/pif;Lb/pif;Lb/pif;)V

    .line 1039
    .line 1040
    .line 1041
    invoke-static {v7}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 1042
    .line 1043
    .line 1044
    move-result-object v0

    .line 1045
    iput-object v0, v6, Lb/it8;->f:Lb/zqn;

    .line 1046
    .line 1047
    iget-object v0, v6, Lb/it8;->a:Lb/pif;

    .line 1048
    .line 1049
    new-instance v2, Lb/lf2;

    .line 1050
    .line 1051
    invoke-direct {v2, v8, v0}, Lb/lf2;-><init>(Lb/ep0;Lb/pif;)V

    .line 1052
    .line 1053
    .line 1054
    iget-object v0, v6, Lb/it8;->d:Lb/pif;

    .line 1055
    .line 1056
    new-instance v3, Lb/huh;

    .line 1057
    .line 1058
    invoke-direct {v3, v8, v0, v2}, Lb/huh;-><init>(Lb/ep0;Lb/pif;Lb/lf2;)V

    .line 1059
    .line 1060
    .line 1061
    invoke-static {v3}, Lb/gba;->b(Lb/zqn;)Lb/zqn;

    .line 1062
    .line 1063
    .line 1064
    move-result-object v0

    .line 1065
    iput-object v0, v6, Lb/it8;->g:Lb/zqn;

    .line 1066
    .line 1067
    sput-object v6, Lb/ooa;->f:Lb/it8;

    .line 1068
    .line 1069
    new-instance v0, Lb/byr;

    .line 1070
    .line 1071
    new-instance v2, Lb/f12;

    .line 1072
    .line 1073
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 1074
    .line 1075
    .line 1076
    new-instance v3, Lb/o02;

    .line 1077
    .line 1078
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 1079
    .line 1080
    .line 1081
    new-instance v4, Lb/p02;

    .line 1082
    .line 1083
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 1084
    .line 1085
    .line 1086
    sget-object v5, Lb/ema;->h:Lb/on8;

    .line 1087
    .line 1088
    invoke-virtual {v5}, Lb/on8;->a()Lb/w3g;

    .line 1089
    .line 1090
    .line 1091
    move-result-object v5

    .line 1092
    sget-object v6, Lb/ema;->h:Lb/on8;

    .line 1093
    .line 1094
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1095
    .line 1096
    .line 1097
    sget-object v6, Lb/kxs;->a:Lb/jxs;

    .line 1098
    .line 1099
    invoke-static {v6}, Lb/dp0;->c(Ljava/lang/Object;)V

    .line 1100
    .line 1101
    .line 1102
    sget-object v7, Lb/tn;->c:Lb/qn8;

    .line 1103
    .line 1104
    iget-object v7, v7, Lb/qn8;->t0:Lb/zqn;

    .line 1105
    .line 1106
    invoke-interface {v7}, Ljavax/inject/Provider;->get()Ljava/lang/Object;

    .line 1107
    .line 1108
    .line 1109
    move-result-object v7

    .line 1110
    check-cast v7, Lb/dw9;

    .line 1111
    .line 1112
    sget-object v8, Lb/ema;->h:Lb/on8;

    .line 1113
    .line 1114
    invoke-virtual {v8}, Lb/on8;->h()Lb/hb7;

    .line 1115
    .line 1116
    .line 1117
    move-result-object v8

    .line 1118
    sget-object v9, Lb/ema;->h:Lb/on8;

    .line 1119
    .line 1120
    invoke-virtual {v9}, Lb/on8;->w()Lb/qnj;

    .line 1121
    .line 1122
    .line 1123
    move-result-object v9

    .line 1124
    sget-object v10, Lb/ema;->h:Lb/on8;

    .line 1125
    .line 1126
    iget-object v10, v10, Lb/on8;->b:Lb/kjm;

    .line 1127
    .line 1128
    new-instance v11, Lb/q02;

    .line 1129
    .line 1130
    const/4 v12, 0x0

    .line 1131
    invoke-direct {v11, v15, v12}, Lb/q02;-><init>(Ljava/lang/Object;I)V

    .line 1132
    .line 1133
    .line 1134
    new-instance v12, Lb/lm1;

    .line 1135
    .line 1136
    const/4 v13, 0x1

    .line 1137
    invoke-direct {v12, v13}, Lb/lm1;-><init>(I)V

    .line 1138
    .line 1139
    .line 1140
    sget-object v13, Lb/tn;->c:Lb/qn8;

    .line 1141
    .line 1142
    iget-object v13, v13, Lb/qn8;->a0:Lb/zqn;

    .line 1143
    .line 1144
    invoke-interface {v13}, Ljavax/inject/Provider;->get()Ljava/lang/Object;

    .line 1145
    .line 1146
    .line 1147
    move-result-object v13

    .line 1148
    check-cast v13, Lb/s9c;

    .line 1149
    .line 1150
    sget-object v14, Lb/ema;->h:Lb/on8;

    .line 1151
    .line 1152
    invoke-virtual {v14}, Lb/on8;->y()Lb/xi8;

    .line 1153
    .line 1154
    .line 1155
    move-result-object v14

    .line 1156
    invoke-direct/range {v0 .. v14}, Lb/byr;-><init>(Lcom/hsh/me/hshAppApplication;Lb/f12;Lb/o02;Lb/p02;Lb/w3g;Lb/ixs;Lb/dw9;Lb/hb7;Lb/qnj;Lb/ijm;Lb/q02;Lb/lm1;Lb/s9c;Lb/xi8;)V

    .line 1157
    .line 1158
    .line 1159
    move-object v8, v0

    .line 1160
    new-instance v0, Lb/ow3;

    .line 1161
    .line 1162
    sget-object v9, Lb/ema;->h:Lb/on8;

    .line 1163
    .line 1164
    const/4 v1, 0x0

    .line 1165
    if-eqz v9, :cond_0

    .line 1166
    .line 1167
    move-object v2, v9

    .line 1168
    goto :goto_0

    .line 1169
    :cond_0
    move-object v2, v1

    .line 1170
    :goto_0
    sget-object v3, Lb/tn;->c:Lb/qn8;

    .line 1171
    .line 1172
    if-eqz v3, :cond_1

    .line 1173
    .line 1174
    goto :goto_1

    .line 1175
    :cond_1
    move-object v3, v1

    .line 1176
    :goto_1
    sget-object v4, Lb/xp5;->f:Lb/rs8;

    .line 1177
    .line 1178
    if-eqz v4, :cond_2

    .line 1179
    .line 1180
    goto :goto_2

    .line 1181
    :cond_2
    move-object v4, v1

    .line 1182
    :goto_2
    sget-object v5, Lb/na6;->f:Lb/ju8;

    .line 1183
    .line 1184
    if-eqz v5, :cond_3

    .line 1185
    .line 1186
    goto :goto_3

    .line 1187
    :cond_3
    move-object v5, v1

    .line 1188
    :goto_3
    sget-object v6, Lb/ooa;->f:Lb/it8;

    .line 1189
    .line 1190
    if-eqz v6, :cond_4

    .line 1191
    .line 1192
    goto :goto_4

    .line 1193
    :cond_4
    move-object v6, v1

    .line 1194
    :goto_4
    sget-object v7, Lb/s0b;->c:Lb/ov8;

    .line 1195
    .line 1196
    if-eqz v7, :cond_5

    .line 1197
    .line 1198
    :goto_5
    move-object/from16 v1, p0

    .line 1199
    .line 1200
    goto :goto_6

    .line 1201
    :cond_5
    move-object v7, v1

    .line 1202
    goto :goto_5

    .line 1203
    :goto_6
    invoke-direct/range {v0 .. v7}, Lb/ow3;-><init>(Lcom/hsh/me/hshAppApplication;Lb/mn6;Lb/jgj;Lb/rs8;Lb/ju8;Lb/it8;Lb/w1n;)V

    .line 1204
    .line 1205
    .line 1206
    new-instance v2, Lb/j12;

    .line 1207
    .line 1208
    invoke-direct {v2, v9}, Lb/j12;-><init>(Lb/mn6;)V

    .line 1209
    .line 1210
    .line 1211
    new-instance v4, Lb/sj6;

    .line 1212
    .line 1213
    invoke-virtual/range {v16 .. v16}, Lb/uo8;->g()Lb/hj7;

    .line 1214
    .line 1215
    .line 1216
    move-result-object v3

    .line 1217
    sget-object v5, Lb/jne;->A:Lb/jne;

    .line 1218
    .line 1219
    invoke-direct {v4, v3, v5}, Lb/sj6;-><init>(Lb/gj7;Lb/hme;)V

    .line 1220
    .line 1221
    .line 1222
    sget-object v3, Lb/ema;->h:Lb/on8;

    .line 1223
    .line 1224
    invoke-virtual {v3}, Lb/on8;->d()Lb/mgp;

    .line 1225
    .line 1226
    .line 1227
    move-result-object v7

    .line 1228
    sget-object v3, Lb/ema;->h:Lb/on8;

    .line 1229
    .line 1230
    invoke-virtual {v3}, Lb/on8;->l()Lb/l9g;

    .line 1231
    .line 1232
    .line 1233
    move-result-object v3

    .line 1234
    sget-object v5, Lb/ema;->h:Lb/on8;

    .line 1235
    .line 1236
    invoke-virtual {v5}, Lb/on8;->h()Lb/hb7;

    .line 1237
    .line 1238
    .line 1239
    move-result-object v10

    .line 1240
    sget-object v5, Lb/ema;->h:Lb/on8;

    .line 1241
    .line 1242
    invoke-virtual {v5}, Lb/on8;->p()Lb/y97;

    .line 1243
    .line 1244
    .line 1245
    move-result-object v5

    .line 1246
    sget-object v6, Lb/tn;->c:Lb/qn8;

    .line 1247
    .line 1248
    iget-object v11, v6, Lb/qn8;->d:Lb/iu8;

    .line 1249
    .line 1250
    new-instance v12, Lb/i71;

    .line 1251
    .line 1252
    new-instance v6, Lb/w02;

    .line 1253
    .line 1254
    invoke-direct {v6, v1}, Lb/w02;-><init>(Ljava/lang/Object;)V

    .line 1255
    .line 1256
    .line 1257
    invoke-direct {v12, v6}, Lb/i71;-><init>(Lb/w02;)V

    .line 1258
    .line 1259
    .line 1260
    iget-object v6, v15, Lb/eo8;->r:Lb/zqn;

    .line 1261
    .line 1262
    invoke-interface {v6}, Ljavax/inject/Provider;->get()Ljava/lang/Object;

    .line 1263
    .line 1264
    .line 1265
    move-result-object v6

    .line 1266
    move-object v13, v6

    .line 1267
    check-cast v13, Lb/yxu;

    .line 1268
    .line 1269
    sget-object v6, Lb/tn;->c:Lb/qn8;

    .line 1270
    .line 1271
    iget-object v6, v6, Lb/qn8;->i:Lb/sw8;

    .line 1272
    .line 1273
    iget-object v6, v6, Lb/sw8;->d:Lb/zqn;

    .line 1274
    .line 1275
    invoke-interface {v6}, Ljavax/inject/Provider;->get()Ljava/lang/Object;

    .line 1276
    .line 1277
    .line 1278
    move-result-object v6

    .line 1279
    check-cast v6, Lb/esr;

    .line 1280
    .line 1281
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1282
    .line 1283
    .line 1284
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1285
    .line 1286
    .line 1287
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1288
    .line 1289
    .line 1290
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1291
    .line 1292
    .line 1293
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1294
    .line 1295
    .line 1296
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1297
    .line 1298
    .line 1299
    move-object v1, v2

    .line 1300
    move-object v2, v8

    .line 1301
    move-object v8, v3

    .line 1302
    move-object v3, v0

    .line 1303
    new-instance v0, Lb/nn8;

    .line 1304
    .line 1305
    new-instance v5, Lb/pv1;

    .line 1306
    .line 1307
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 1308
    .line 1309
    .line 1310
    new-instance v6, Lb/gj;

    .line 1311
    .line 1312
    const/4 v9, 0x4

    .line 1313
    invoke-direct {v6, v9}, Lb/gj;-><init>(I)V

    .line 1314
    .line 1315
    .line 1316
    move-object/from16 v9, p0

    .line 1317
    .line 1318
    invoke-direct/range {v0 .. v13}, Lb/nn8;-><init>(Lb/j12;Lb/byr;Lb/ow3;Lb/sj6;Lb/pv1;Lb/gj;Lb/mgp;Lb/l9g;Lcom/hsh/me/hshAppApplication;Lb/hb7;Lb/vdl;Lb/i71;Lb/yxu;)V

    .line 1319
    .line 1320
    .line 1321
    move-object v1, v9

    .line 1322
    iput-object v0, v1, Lcom/hsh/me/hshAppApplication;->p:Lb/nn8;

    .line 1323
    .line 1324
    new-instance v0, Lb/r02;

    .line 1325
    .line 1326
    const/4 v8, 0x0

    .line 1327
    invoke-direct {v0, v1, v8}, Lb/r02;-><init>(Ljava/lang/Object;I)V

    .line 1328
    .line 1329
    .line 1330
    invoke-static {v0}, Lb/umg;->b(Lkotlin/jvm/functions/Function0;)Lb/okg;

    .line 1331
    .line 1332
    .line 1333
    move-result-object v0

    .line 1334
    sput-object v0, Lb/mh6$a;->a:Lb/okg;

    .line 1335
    .line 1336
    new-instance v0, Lb/c12;

    .line 1337
    .line 1338
    invoke-direct {v0, v1, v8}, Lb/c12;-><init>(Ljava/lang/Object;I)V

    .line 1339
    .line 1340
    .line 1341
    sget-object v2, Lb/nbx;->a:Lb/nbx$a;

    .line 1342
    .line 1343
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1344
    .line 1345
    .line 1346
    sput-object v0, Lb/nbx$a;->b:Lb/c12;

    .line 1347
    .line 1348
    return-void
.end method

.method public final onCreate()V
    .locals 14

    .line 1
    sget-object v0, Lb/bmt;->b:Lb/d7j;

    .line 2
    .line 3
    sget-object v1, Lb/n72;->a:Lb/n72;

    .line 4
    .line 5
    check-cast v0, Lb/xjr;

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Lb/xjr;->setValue(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    sget-object v0, Lb/bmt;->a:Lb/d7j;

    .line 11
    .line 12
    sget-object v1, Lb/d92;->a:Lb/d92;

    .line 13
    .line 14
    check-cast v0, Lb/xjr;

    .line 15
    .line 16
    invoke-virtual {v0, v1}, Lb/xjr;->setValue(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    sget-object v0, Lb/bmt;->c:Lb/d7j;

    .line 20
    .line 21
    sget-object v1, Lb/wc2;->a:Lb/wc2;

    .line 22
    .line 23
    check-cast v0, Lb/xjr;

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Lb/xjr;->setValue(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    invoke-static {p0}, Lb/gvm;->a(Landroid/content/Context;)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-eqz v0, :cond_4

    .line 33
    .line 34
    sget-object v0, Lb/kxs;->a:Lb/jxs;

    .line 35
    .line 36
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 40
    .line 41
    .line 42
    move-result-wide v1

    .line 43
    iget-object v3, p0, Lb/u03;->j:Lb/vji;

    .line 44
    .line 45
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 46
    .line 47
    .line 48
    sget-object v4, Lb/vji;->d:Lb/jxs;

    .line 49
    .line 50
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 51
    .line 52
    .line 53
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 54
    .line 55
    .line 56
    invoke-super {p0}, Lb/x12;->onCreate()V

    .line 57
    .line 58
    .line 59
    sget-object v4, Lb/cao;->a:Lb/cao$b;

    .line 60
    .line 61
    sget-object v4, Lb/cao;->a:Lb/cao$b;

    .line 62
    .line 63
    if-nez v4, :cond_2

    .line 64
    .line 65
    sget-object v4, Lb/npo;->a:Lb/npo;

    .line 66
    .line 67
    sput-object v4, Lb/cao;->a:Lb/cao$b;

    .line 68
    .line 69
    iget-object v4, p0, Lcom/hsh/me/hshAppApplication;->p:Lb/nn8;

    .line 70
    .line 71
    iget-object v6, v4, Lb/nn8;->c:Lb/mgp;

    .line 72
    .line 73
    iget-object v4, v4, Lb/nn8;->r0:Lb/zqn;

    .line 74
    .line 75
    invoke-interface {v4}, Ljavax/inject/Provider;->get()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    move-object v7, v4

    .line 80
    check-cast v7, Lb/qnj;

    .line 81
    .line 82
    new-instance v8, Lb/m36;

    .line 83
    .line 84
    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    .line 85
    .line 86
    .line 87
    new-instance v4, Lb/jgm;

    .line 88
    .line 89
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 90
    .line 91
    .line 92
    new-instance v5, Lb/my4;

    .line 93
    .line 94
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 95
    .line 96
    .line 97
    new-instance v9, Lb/hle;

    .line 98
    .line 99
    invoke-direct {v9}, Ljava/lang/Object;-><init>()V

    .line 100
    .line 101
    .line 102
    new-instance v10, Lb/uv7;

    .line 103
    .line 104
    sget-object v11, Lb/cf9;->a:Lb/cf9;

    .line 105
    .line 106
    invoke-virtual {v11}, Lb/cf9;->a()Lb/vpe;

    .line 107
    .line 108
    .line 109
    move-result-object v12

    .line 110
    invoke-direct {v10, v12, v0, v4}, Lb/uv7;-><init>(Lb/vpe;Lb/ixs;Lb/jgm;)V

    .line 111
    .line 112
    .line 113
    new-instance v12, Lb/bz7;

    .line 114
    .line 115
    invoke-virtual {v11}, Lb/cf9;->a()Lb/vpe;

    .line 116
    .line 117
    .line 118
    move-result-object v4

    .line 119
    invoke-direct {v12, v4, v0, v5}, Lb/bz7;-><init>(Lb/vpe;Lb/ixs;Lb/my4;)V

    .line 120
    .line 121
    .line 122
    new-instance v11, Lb/xrq;

    .line 123
    .line 124
    invoke-direct {v11}, Ljava/lang/Object;-><init>()V

    .line 125
    .line 126
    .line 127
    new-instance v13, Lb/r39;

    .line 128
    .line 129
    invoke-direct {v13}, Ljava/lang/Object;-><init>()V

    .line 130
    .line 131
    .line 132
    new-instance v5, Lcom/hsh/me/comms/networkdebug/NetworkDebugWorker$a;

    .line 133
    .line 134
    invoke-direct/range {v5 .. v13}, Lcom/hsh/me/comms/networkdebug/NetworkDebugWorker$a;-><init>(Lb/mgp;Lb/qnj;Lb/m36;Lb/hle;Lb/uv7;Lb/xrq;Lb/bz7;Lb/r39;)V

    .line 135
    .line 136
    .line 137
    new-instance v0, Lcom/hsh/me/lexem/UpdateLexemesBackgroundWorker$a;

    .line 138
    .line 139
    const-class v4, Lcom/hsh/me/lexem/UpdateLexemesBackgroundWorker;

    .line 140
    .line 141
    invoke-direct {v0, v4}, Lb/sdr;-><init>(Ljava/lang/Class;)V

    .line 142
    .line 143
    .line 144
    filled-new-array {v5, v0}, [Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v0

    .line 148
    const/4 v4, 0x2

    .line 149
    invoke-static {v4, v0}, Lb/a2f;->k(I[Ljava/lang/Object;)Lb/a2f;

    .line 150
    .line 151
    .line 152
    move-result-object v0

    .line 153
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 154
    .line 155
    .line 156
    move-result-object v0

    .line 157
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 158
    .line 159
    .line 160
    move-result v5

    .line 161
    if-eqz v5, :cond_0

    .line 162
    .line 163
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object v5

    .line 167
    check-cast v5, Lb/s9x;

    .line 168
    .line 169
    iget-object v6, p0, Lb/nm6;->a:Lb/kp9;

    .line 170
    .line 171
    iget-object v6, v6, Lb/kp9;->a:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 172
    .line 173
    invoke-virtual {v6, v5}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    .line 174
    .line 175
    .line 176
    goto :goto_0

    .line 177
    :cond_0
    new-instance v0, Landroid/app/ActivityManager$RunningAppProcessInfo;

    .line 178
    .line 179
    invoke-direct {v0}, Landroid/app/ActivityManager$RunningAppProcessInfo;-><init>()V

    .line 180
    .line 181
    .line 182
    :try_start_0
    invoke-static {v0}, Landroid/app/ActivityManager;->getMyMemoryState(Landroid/app/ActivityManager$RunningAppProcessInfo;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 183
    .line 184
    .line 185
    goto :goto_1

    .line 186
    :catch_0
    const/4 v0, 0x0

    .line 187
    :goto_1
    invoke-static {v0}, Lb/pvm;->a(Landroid/app/ActivityManager$RunningAppProcessInfo;)Z

    .line 188
    .line 189
    .line 190
    move-result v0

    .line 191
    if-nez v0, :cond_1

    .line 192
    .line 193
    sget-object v0, Lb/ema;->h:Lb/on8;

    .line 194
    .line 195
    invoke-virtual {v0}, Lb/on8;->a()Lb/w3g;

    .line 196
    .line 197
    .line 198
    move-result-object v0

    .line 199
    iget-object v5, v3, Lb/vji;->c:Ljava/util/Random;

    .line 200
    .line 201
    const/16 v6, 0x64

    .line 202
    .line 203
    invoke-virtual {v5, v6}, Ljava/util/Random;->nextInt(I)I

    .line 204
    .line 205
    .line 206
    move-result v5

    .line 207
    if-nez v5, :cond_1

    .line 208
    .line 209
    new-instance v5, Landroid/os/Handler;

    .line 210
    .line 211
    invoke-virtual {p0}, Landroid/content/Context;->getMainLooper()Landroid/os/Looper;

    .line 212
    .line 213
    .line 214
    move-result-object v6

    .line 215
    invoke-direct {v5, v6}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 216
    .line 217
    .line 218
    new-instance v6, Lb/ov0;

    .line 219
    .line 220
    invoke-direct {v6, v4, v3, v0}, Lb/ov0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 221
    .line 222
    .line 223
    const-wide/16 v3, 0x1f40

    .line 224
    .line 225
    invoke-virtual {v5, v6, v3, v4}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 226
    .line 227
    .line 228
    :cond_1
    sget-object v0, Lb/d61;->a:Lb/d61;

    .line 229
    .line 230
    sget-object v3, Landroidx/lifecycle/ProcessLifecycleOwner;->i:Landroidx/lifecycle/ProcessLifecycleOwner;

    .line 231
    .line 232
    iget-object v3, v3, Landroidx/lifecycle/ProcessLifecycleOwner;->f:Landroidx/lifecycle/m;

    .line 233
    .line 234
    invoke-virtual {v3, v0}, Landroidx/lifecycle/m;->a(Lb/lug;)V

    .line 235
    .line 236
    .line 237
    iget-object v0, p0, Lcom/hsh/me/hshAppApplication;->p:Lb/nn8;

    .line 238
    .line 239
    invoke-virtual {v0}, Lb/nn8;->k()Lb/h61;

    .line 240
    .line 241
    .line 242
    move-result-object v0

    .line 243
    sget-wide v3, Lb/u03;->k:J

    .line 244
    .line 245
    invoke-interface {v0, v3, v4, v1, v2}, Lb/h61;->a(JJ)V

    .line 246
    .line 247
    .line 248
    iget-object v0, p0, Lcom/hsh/me/hshAppApplication;->p:Lb/nn8;

    .line 249
    .line 250
    invoke-virtual {v0}, Lb/nn8;->d()Lb/giu;

    .line 251
    .line 252
    .line 253
    move-result-object v0

    .line 254
    invoke-interface {v0, v3, v4}, Lb/giu;->d(J)V

    .line 255
    .line 256
    .line 257
    sget-object v0, Lb/ema;->h:Lb/on8;

    .line 258
    .line 259
    invoke-virtual {v0}, Lb/on8;->q()Lb/bz0;

    .line 260
    .line 261
    .line 262
    move-result-object v0

    .line 263
    invoke-interface {v0}, Lb/bz0;->c()V

    .line 264
    .line 265
    .line 266
    goto :goto_2

    .line 267
    :cond_2
    instance-of v0, v4, Lb/cao$a;

    .line 268
    .line 269
    if-eqz v0, :cond_3

    .line 270
    .line 271
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 272
    .line 273
    const-string v1, "Attempting to set a errorHandler after using RIB code."

    .line 274
    .line 275
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 276
    .line 277
    .line 278
    throw v0

    .line 279
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 280
    .line 281
    const-string v1, "Attempting to set a errorHandler after one has previously been set."

    .line 282
    .line 283
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 284
    .line 285
    .line 286
    throw v0

    .line 287
    :cond_4
    invoke-virtual {p0}, Lcom/hsh/me/hshAppApplication;->r()V

    .line 288
    .line 289
    .line 290
    :goto_2
    iget-object v0, p0, Lb/nm6;->b:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 291
    .line 292
    const/4 v1, 0x1

    .line 293
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 294
    .line 295
    .line 296
    sget-object v0, Lb/r22;->a:[Lb/r22;

    .line 297
    .line 298
    return-void
.end method

.method public final r()V
    .locals 14

    .line 1
    sget-object v0, Lb/kxs;->a:Lb/jxs;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 7
    .line 8
    .line 9
    move-result-wide v1

    .line 10
    new-instance v3, Lb/ahr;

    .line 11
    .line 12
    new-instance v4, Lb/zgr;

    .line 13
    .line 14
    const-wide/16 v5, 0x1388

    .line 15
    .line 16
    const-string v7, "AND-38783-light-app-oncreate-slow-5s"

    .line 17
    .line 18
    invoke-direct {v4, v5, v6, v7}, Lb/zgr;-><init>(JLjava/lang/String;)V

    .line 19
    .line 20
    .line 21
    new-instance v5, Lb/zgr;

    .line 22
    .line 23
    const-wide/16 v6, 0x3a98

    .line 24
    .line 25
    const-string v8, "AND-38783-light-app-oncreate-slow-15s"

    .line 26
    .line 27
    invoke-direct {v5, v6, v7, v8}, Lb/zgr;-><init>(JLjava/lang/String;)V

    .line 28
    .line 29
    .line 30
    filled-new-array {v4, v5}, [Lb/zgr;

    .line 31
    .line 32
    .line 33
    move-result-object v4

    .line 34
    invoke-static {v4}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 35
    .line 36
    .line 37
    move-result-object v4

    .line 38
    new-instance v5, Lb/im1;

    .line 39
    .line 40
    const/4 v6, 0x1

    .line 41
    invoke-direct {v5, v6}, Lb/im1;-><init>(I)V

    .line 42
    .line 43
    .line 44
    invoke-direct {v3, v4, v5, v0}, Lb/ahr;-><init>(Ljava/util/List;Lkotlin/jvm/functions/Function0;Lb/ixs;)V

    .line 45
    .line 46
    .line 47
    iget-object v4, v3, Lb/ahr;->d:Ljava/util/concurrent/atomic/AtomicLong;

    .line 48
    .line 49
    invoke-interface {v0}, Lb/ixs;->elapsedRealtime()J

    .line 50
    .line 51
    .line 52
    move-result-wide v5

    .line 53
    invoke-virtual {v4, v5, v6}, Ljava/util/concurrent/atomic/AtomicLong;->set(J)V

    .line 54
    .line 55
    .line 56
    invoke-interface {v0}, Lb/ixs;->elapsedRealtime()J

    .line 57
    .line 58
    .line 59
    move-result-wide v4

    .line 60
    new-instance v6, Lb/nme;

    .line 61
    .line 62
    sget-object v7, Lb/jne;->A:Lb/jne;

    .line 63
    .line 64
    const-string v8, "getInstance(...)"

    .line 65
    .line 66
    invoke-static {v7, v8}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullExpressionValue(Ljava/lang/Object;Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    new-instance v8, Lb/tvm;

    .line 70
    .line 71
    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    .line 72
    .line 73
    .line 74
    sget-object v9, Lb/e90;->c:Lb/e90;

    .line 75
    .line 76
    invoke-direct {v6, v7, v9, v8}, Lb/nme;-><init>(Lb/jne;Lb/e90;Lb/svm;)V

    .line 77
    .line 78
    .line 79
    new-instance v7, Lb/z3g;

    .line 80
    .line 81
    new-instance v8, Lb/n3g;

    .line 82
    .line 83
    invoke-direct {v8, v0}, Lb/n3g;-><init>(Lb/g7j;)V

    .line 84
    .line 85
    .line 86
    invoke-direct {v7, v8, v6}, Lb/z3g;-><init>(Lb/lit;Lb/o3g;)V

    .line 87
    .line 88
    .line 89
    new-instance v6, Lb/ygr;

    .line 90
    .line 91
    invoke-interface {v0}, Lb/ixs;->elapsedRealtime()J

    .line 92
    .line 93
    .line 94
    move-result-wide v8

    .line 95
    sub-long/2addr v8, v4

    .line 96
    const-string v4, "CreateJinbaService"

    .line 97
    .line 98
    invoke-direct {v6, v4, v8, v9}, Lb/ygr;-><init>(Ljava/lang/String;J)V

    .line 99
    .line 100
    .line 101
    iget-object v4, v3, Lb/ahr;->e:Ljava/util/List;

    .line 102
    .line 103
    invoke-interface {v4, v6}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    new-instance v5, Lb/hx0;

    .line 107
    .line 108
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 109
    .line 110
    .line 111
    invoke-static {p0, v5}, Lb/eeq;->a(Landroid/content/Context;Lb/hx0;)V

    .line 112
    .line 113
    .line 114
    invoke-interface {v0}, Lb/ixs;->elapsedRealtime()J

    .line 115
    .line 116
    .line 117
    move-result-wide v5

    .line 118
    invoke-static {p0}, Lb/y9c;->f(Landroid/content/Context;)V

    .line 119
    .line 120
    .line 121
    new-instance v8, Lb/ygr;

    .line 122
    .line 123
    invoke-interface {v0}, Lb/ixs;->elapsedRealtime()J

    .line 124
    .line 125
    .line 126
    move-result-wide v9

    .line 127
    sub-long/2addr v9, v5

    .line 128
    const-string v5, "InitFirebase"

    .line 129
    .line 130
    invoke-direct {v8, v5, v9, v10}, Lb/ygr;-><init>(Ljava/lang/String;J)V

    .line 131
    .line 132
    .line 133
    invoke-interface {v4, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    invoke-interface {v0}, Lb/ixs;->elapsedRealtime()J

    .line 137
    .line 138
    .line 139
    move-result-wide v5

    .line 140
    invoke-virtual {p0}, Lcom/hsh/me/hshAppApplication;->i()V

    .line 141
    .line 142
    .line 143
    new-instance v8, Lb/ygr;

    .line 144
    .line 145
    invoke-interface {v0}, Lb/ixs;->elapsedRealtime()J

    .line 146
    .line 147
    .line 148
    move-result-wide v9

    .line 149
    sub-long/2addr v9, v5

    .line 150
    const-string v5, "ConfigureBuildUtils"

    .line 151
    .line 152
    invoke-direct {v8, v5, v9, v10}, Lb/ygr;-><init>(Ljava/lang/String;J)V

    .line 153
    .line 154
    .line 155
    invoke-interface {v4, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    invoke-interface {v0}, Lb/ixs;->elapsedRealtime()J

    .line 159
    .line 160
    .line 161
    move-result-wide v5

    .line 162
    invoke-virtual {p0}, Lcom/hsh/me/hshAppApplication;->n()V

    .line 163
    .line 164
    .line 165
    new-instance v8, Lb/ygr;

    .line 166
    .line 167
    invoke-interface {v0}, Lb/ixs;->elapsedRealtime()J

    .line 168
    .line 169
    .line 170
    move-result-wide v9

    .line 171
    sub-long/2addr v9, v5

    .line 172
    const-string v5, "InitBuildProperties"

    .line 173
    .line 174
    invoke-direct {v8, v5, v9, v10}, Lb/ygr;-><init>(Ljava/lang/String;J)V

    .line 175
    .line 176
    .line 177
    invoke-interface {v4, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    new-instance v5, Lb/x02;

    .line 181
    .line 182
    invoke-direct {v5, p0}, Lb/x02;-><init>(Lcom/hsh/me/hshAppApplication;)V

    .line 183
    .line 184
    .line 185
    invoke-interface {v0}, Lb/ixs;->elapsedRealtime()J

    .line 186
    .line 187
    .line 188
    move-result-wide v8

    .line 189
    invoke-virtual {v5}, Lb/x02;->run()V

    .line 190
    .line 191
    .line 192
    new-instance v5, Lb/ygr;

    .line 193
    .line 194
    invoke-interface {v0}, Lb/ixs;->elapsedRealtime()J

    .line 195
    .line 196
    .line 197
    move-result-wide v10

    .line 198
    sub-long/2addr v10, v8

    .line 199
    const-string v6, "ConfigureHotpanel"

    .line 200
    .line 201
    invoke-direct {v5, v6, v10, v11}, Lb/ygr;-><init>(Ljava/lang/String;J)V

    .line 202
    .line 203
    .line 204
    invoke-interface {v4, v5}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 205
    .line 206
    .line 207
    invoke-interface {v0}, Lb/ixs;->elapsedRealtime()J

    .line 208
    .line 209
    .line 210
    move-result-wide v5

    .line 211
    invoke-static {}, Lb/uhp;->a()V

    .line 212
    .line 213
    .line 214
    new-instance v8, Lb/ygr;

    .line 215
    .line 216
    invoke-interface {v0}, Lb/ixs;->elapsedRealtime()J

    .line 217
    .line 218
    .line 219
    move-result-wide v9

    .line 220
    sub-long/2addr v9, v5

    .line 221
    const-string v5, "RegisterErrorReporter"

    .line 222
    .line 223
    invoke-direct {v8, v5, v9, v10}, Lb/ygr;-><init>(Ljava/lang/String;J)V

    .line 224
    .line 225
    .line 226
    invoke-interface {v4, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 227
    .line 228
    .line 229
    invoke-interface {v0}, Lb/ixs;->elapsedRealtime()J

    .line 230
    .line 231
    .line 232
    move-result-wide v5

    .line 233
    new-instance v8, Lb/qwn;

    .line 234
    .line 235
    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    .line 236
    .line 237
    .line 238
    new-instance v9, Lb/fxn;

    .line 239
    .line 240
    invoke-direct {v9}, Lb/fxn;-><init>()V

    .line 241
    .line 242
    .line 243
    new-instance v10, Lb/tvn;

    .line 244
    .line 245
    new-instance v11, Lb/qwn$a;

    .line 246
    .line 247
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 248
    .line 249
    .line 250
    move-result-object v12

    .line 251
    const-string v13, "getApplicationContext(...)"

    .line 252
    .line 253
    invoke-static {v12, v13}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullExpressionValue(Ljava/lang/Object;Ljava/lang/String;)V

    .line 254
    .line 255
    .line 256
    invoke-direct {v11, v12, v7, v9}, Lb/qwn$a;-><init>(Landroid/content/Context;Lb/z3g;Lb/fxn;)V

    .line 257
    .line 258
    .line 259
    invoke-direct {v10, v11}, Lb/tvn;-><init>(Lb/qwn$a;)V

    .line 260
    .line 261
    .line 262
    invoke-virtual {v9}, Lb/fxn;->b()Lb/vpp;

    .line 263
    .line 264
    .line 265
    move-result-object v9

    .line 266
    new-instance v11, Lb/pwn;

    .line 267
    .line 268
    invoke-direct {v11, v8, v10}, Lb/pwn;-><init>(Lb/qwn;Lb/tvn;)V

    .line 269
    .line 270
    .line 271
    invoke-virtual {v9, v11}, Lb/vpp;->b(Ljava/lang/Runnable;)Lb/f8a;

    .line 272
    .line 273
    .line 274
    new-instance v8, Lb/ygr;

    .line 275
    .line 276
    invoke-interface {v0}, Lb/ixs;->elapsedRealtime()J

    .line 277
    .line 278
    .line 279
    move-result-wide v9

    .line 280
    sub-long/2addr v9, v5

    .line 281
    const-string v5, "AttachPushModule"

    .line 282
    .line 283
    invoke-direct {v8, v5, v9, v10}, Lb/ygr;-><init>(Ljava/lang/String;J)V

    .line 284
    .line 285
    .line 286
    invoke-interface {v4, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 287
    .line 288
    .line 289
    invoke-interface {v0}, Lb/ixs;->elapsedRealtime()J

    .line 290
    .line 291
    .line 292
    move-result-wide v5

    .line 293
    new-instance v8, Lb/l61;

    .line 294
    .line 295
    new-instance v9, Lb/dw9;

    .line 296
    .line 297
    invoke-direct {v9, p0}, Lb/dw9;-><init>(Landroid/content/Context;)V

    .line 298
    .line 299
    .line 300
    invoke-direct {v8, p0, v0, v7, v9}, Lb/l61;-><init>(Landroid/content/Context;Lb/ixs;Lb/w3g;Lb/dw9;)V

    .line 301
    .line 302
    .line 303
    new-instance v7, Lb/ygr;

    .line 304
    .line 305
    invoke-interface {v0}, Lb/ixs;->elapsedRealtime()J

    .line 306
    .line 307
    .line 308
    move-result-wide v9

    .line 309
    sub-long/2addr v9, v5

    .line 310
    const-string v5, "CreateApplicationOnCreateTracker"

    .line 311
    .line 312
    invoke-direct {v7, v5, v9, v10}, Lb/ygr;-><init>(Ljava/lang/String;J)V

    .line 313
    .line 314
    .line 315
    invoke-interface {v4, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 316
    .line 317
    .line 318
    invoke-interface {v0}, Lb/ixs;->elapsedRealtime()J

    .line 319
    .line 320
    .line 321
    move-result-wide v5

    .line 322
    sget-wide v9, Lb/u03;->k:J

    .line 323
    .line 324
    invoke-virtual {v8, v9, v10, v1, v2}, Lb/l61;->a(JJ)V

    .line 325
    .line 326
    .line 327
    new-instance v1, Lb/ygr;

    .line 328
    .line 329
    invoke-interface {v0}, Lb/ixs;->elapsedRealtime()J

    .line 330
    .line 331
    .line 332
    move-result-wide v7

    .line 333
    sub-long/2addr v7, v5

    .line 334
    const-string v0, "TrackOnApplicationCreateFinished"

    .line 335
    .line 336
    invoke-direct {v1, v0, v7, v8}, Lb/ygr;-><init>(Ljava/lang/String;J)V

    .line 337
    .line 338
    .line 339
    invoke-interface {v4, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 340
    .line 341
    .line 342
    invoke-virtual {v3}, Lb/ahr;->b()V

    .line 343
    .line 344
    .line 345
    return-void
.end method

.method public final s()V
    .locals 6

    .line 1
    sget-object v0, Lb/ix0;->a:Lb/ix0;

    .line 2
    .line 3
    invoke-super {p0}, Lb/x12;->s()V

    .line 4
    .line 5
    .line 6
    sget-object v1, Lb/ema;->h:Lb/on8;

    .line 7
    .line 8
    iget-object v1, v1, Lb/on8;->A0:Lb/zqn;

    .line 9
    .line 10
    invoke-interface {v1}, Ljavax/inject/Provider;->get()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    check-cast v1, Lb/jnj;

    .line 15
    .line 16
    invoke-interface {v1}, Lb/jnj;->a()V

    .line 17
    .line 18
    .line 19
    sget-object v1, Lb/ema;->h:Lb/on8;

    .line 20
    .line 21
    iget-object v1, v1, Lb/on8;->Z0:Lb/zqn;

    .line 22
    .line 23
    invoke-interface {v1}, Ljavax/inject/Provider;->get()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    check-cast v1, Lb/xzl;

    .line 28
    .line 29
    sget-object v1, Lb/n81;->g:Lb/cwq;

    .line 30
    .line 31
    new-instance v2, Lb/vig;

    .line 32
    .line 33
    invoke-direct {v2, p0}, Lb/vig;-><init>(Lcom/hsh/me/hshAppApplication;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0, v1, v2}, Lb/ix0;->c(Lb/cwq;Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    sget-object v1, Lb/n81;->d:Lb/cwq;

    .line 40
    .line 41
    sget-object v2, Lb/tn;->c:Lb/qn8;

    .line 42
    .line 43
    invoke-virtual {v2}, Lb/qn8;->E()Lb/xw1;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    invoke-virtual {v0, v1, v2}, Lb/ix0;->c(Lb/cwq;Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    sget-object v1, Lb/x95;->e:Lb/cwq;

    .line 51
    .line 52
    invoke-static {v1}, Lb/ix0;->a(Lb/cwq;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    check-cast v1, Lb/p1c;

    .line 57
    .line 58
    sget-object v2, Lb/n81;->k:Lb/cwq;

    .line 59
    .line 60
    new-instance v3, Lb/z02;

    .line 61
    .line 62
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v0, v2, v3}, Lb/ix0;->c(Lb/cwq;Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    new-instance v0, Lb/nxo;

    .line 69
    .line 70
    invoke-direct {v0, p0, v1}, Lb/nxo;-><init>(Lcom/hsh/me/hshAppApplication;Lb/p1c;)V

    .line 71
    .line 72
    .line 73
    sget-object v2, Lb/kxo;->c:Lb/kxo;

    .line 74
    .line 75
    sget-object v3, Lb/pu1;->a:Lb/juo;

    .line 76
    .line 77
    new-instance v4, Lb/oxo;

    .line 78
    .line 79
    invoke-direct {v4, v0}, Lb/oxo;-><init>(Lb/nxo;)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {v2, v3, v4}, Lb/kxo;->b(Lb/juo;Lb/dxb;)V

    .line 83
    .line 84
    .line 85
    sget-object v3, Lb/pu1;->c:Lb/juo;

    .line 86
    .line 87
    new-instance v4, Lb/txo;

    .line 88
    .line 89
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v2, v3, v4}, Lb/kxo;->b(Lb/juo;Lb/dxb;)V

    .line 93
    .line 94
    .line 95
    sget-object v3, Lb/pu1;->b:Lb/juo;

    .line 96
    .line 97
    new-instance v4, Lb/uxo;

    .line 98
    .line 99
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v2, v3, v4}, Lb/kxo;->b(Lb/juo;Lb/dxb;)V

    .line 103
    .line 104
    .line 105
    sget-object v3, Lb/nq;->b:Lb/juo;

    .line 106
    .line 107
    new-instance v4, Lb/vxo;

    .line 108
    .line 109
    invoke-direct {v4, v0}, Lb/vxo;-><init>(Lb/nxo;)V

    .line 110
    .line 111
    .line 112
    invoke-virtual {v2, v3, v4}, Lb/kxo;->b(Lb/juo;Lb/dxb;)V

    .line 113
    .line 114
    .line 115
    sget-object v3, Lb/cq;->a:Lb/juo;

    .line 116
    .line 117
    new-instance v4, Lb/wxo;

    .line 118
    .line 119
    invoke-direct {v4, v0}, Lb/wxo;-><init>(Lb/nxo;)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v2, v3, v4}, Lb/kxo;->b(Lb/juo;Lb/dxb;)V

    .line 123
    .line 124
    .line 125
    sget-object v3, Lb/pu1;->d:Lb/juo;

    .line 126
    .line 127
    new-instance v4, Lb/xxo;

    .line 128
    .line 129
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v2, v3, v4}, Lb/kxo;->b(Lb/juo;Lb/dxb;)V

    .line 133
    .line 134
    .line 135
    sget-object v3, Lb/t06;->i:Lb/juo;

    .line 136
    .line 137
    new-instance v4, Lb/yxo;

    .line 138
    .line 139
    invoke-direct {v4, v0}, Lb/yxo;-><init>(Lb/nxo;)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v2, v3, v4}, Lb/kxo;->b(Lb/juo;Lb/dxb;)V

    .line 143
    .line 144
    .line 145
    sget-object v4, Lb/nxq;->j:Lb/juo;

    .line 146
    .line 147
    new-instance v5, Lb/zxo;

    .line 148
    .line 149
    invoke-direct {v5, v0}, Lb/zxo;-><init>(Lb/nxo;)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v2, v4, v5}, Lb/kxo;->b(Lb/juo;Lb/dxb;)V

    .line 153
    .line 154
    .line 155
    sget-object v4, Lb/pu1;->e:Lb/juo;

    .line 156
    .line 157
    new-instance v5, Lb/pxo;

    .line 158
    .line 159
    invoke-direct {v5, v0}, Lb/pxo;-><init>(Lb/nxo;)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {v2, v4, v5}, Lb/kxo;->b(Lb/juo;Lb/dxb;)V

    .line 163
    .line 164
    .line 165
    sget-object v4, Lb/pu1;->f:Lb/juo;

    .line 166
    .line 167
    new-instance v5, Lb/qxo;

    .line 168
    .line 169
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 170
    .line 171
    .line 172
    invoke-virtual {v2, v4, v5}, Lb/kxo;->b(Lb/juo;Lb/dxb;)V

    .line 173
    .line 174
    .line 175
    sget-object v4, Lb/pu1;->g:Lb/juo;

    .line 176
    .line 177
    new-instance v5, Lb/rxo;

    .line 178
    .line 179
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 180
    .line 181
    .line 182
    invoke-virtual {v2, v4, v5}, Lb/kxo;->b(Lb/juo;Lb/dxb;)V

    .line 183
    .line 184
    .line 185
    sget-object v4, Lb/dom;->a:Lb/dom$a;

    .line 186
    .line 187
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 188
    .line 189
    .line 190
    sget-object v4, Lb/dom$a;->b:Lb/juo;

    .line 191
    .line 192
    new-instance v5, Lb/sxo;

    .line 193
    .line 194
    invoke-direct {v5, v0}, Lb/sxo;-><init>(Lb/nxo;)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {v2, v4, v5}, Lb/kxo;->b(Lb/juo;Lb/dxb;)V

    .line 198
    .line 199
    .line 200
    invoke-static {v3}, Lb/kxo;->a(Lb/juo;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    sget-object v0, Lb/tn;->c:Lb/qn8;

    .line 204
    .line 205
    iget-object v0, v0, Lb/qn8;->b:Lb/uo8;

    .line 206
    .line 207
    invoke-virtual {v0}, Lb/uo8;->h()Lb/y3u;

    .line 208
    .line 209
    .line 210
    sget-object v0, Lb/tn;->c:Lb/qn8;

    .line 211
    .line 212
    iget-object v0, v0, Lb/qn8;->b:Lb/uo8;

    .line 213
    .line 214
    iget-object v0, v0, Lb/uo8;->l:Lb/zqn;

    .line 215
    .line 216
    invoke-interface {v0}, Ljavax/inject/Provider;->get()Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    move-result-object v0

    .line 220
    check-cast v0, Lb/ubx;

    .line 221
    .line 222
    sget-object v0, Lb/tn;->c:Lb/qn8;

    .line 223
    .line 224
    iget-object v0, v0, Lb/qn8;->b:Lb/uo8;

    .line 225
    .line 226
    invoke-virtual {v0}, Lb/uo8;->i()Lb/p2w;

    .line 227
    .line 228
    .line 229
    sget-object v0, Lb/f92;->i:Lb/f92;

    .line 230
    .line 231
    invoke-interface {v1, v0}, Lb/p1c;->j(Lb/cu9;)Z

    .line 232
    .line 233
    .line 234
    move-result v0

    .line 235
    if-eqz v0, :cond_0

    .line 236
    .line 237
    sget-object v0, Lb/ema;->h:Lb/on8;

    .line 238
    .line 239
    iget-object v0, v0, Lb/on8;->h1:Lb/zqn;

    .line 240
    .line 241
    invoke-interface {v0}, Ljavax/inject/Provider;->get()Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object v0

    .line 245
    check-cast v0, Lb/jz2;

    .line 246
    .line 247
    invoke-interface {v0}, Lb/jz2;->init()V

    .line 248
    .line 249
    .line 250
    :cond_0
    new-instance v0, Lb/a12;

    .line 251
    .line 252
    const/4 v1, 0x0

    .line 253
    invoke-direct {v0, p0, v1}, Lb/a12;-><init>(Ljava/lang/Object;I)V

    .line 254
    .line 255
    .line 256
    sget-object v1, Lb/mf0;->S:Lb/mf0;

    .line 257
    .line 258
    invoke-virtual {p0, v1, v0}, Lb/u03;->q(Lb/mf0;Lkotlin/jvm/functions/Function0;)V

    .line 259
    .line 260
    .line 261
    sget-object v0, Lb/tn;->c:Lb/qn8;

    .line 262
    .line 263
    iget-object v0, v0, Lb/qn8;->C:Lb/zqn;

    .line 264
    .line 265
    invoke-interface {v0}, Ljavax/inject/Provider;->get()Ljava/lang/Object;

    .line 266
    .line 267
    .line 268
    move-result-object v0

    .line 269
    check-cast v0, Lb/rwv;

    .line 270
    .line 271
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 272
    .line 273
    .line 274
    new-instance v1, Lb/nwv;

    .line 275
    .line 276
    new-instance v1, Lb/rwv$a;

    .line 277
    .line 278
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 279
    .line 280
    .line 281
    move-result-object v2

    .line 282
    const-string v3, "getApplicationContext(...)"

    .line 283
    .line 284
    invoke-static {v2, v3}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullExpressionValue(Ljava/lang/Object;Ljava/lang/String;)V

    .line 285
    .line 286
    .line 287
    invoke-direct {v1, v0, v2}, Lb/rwv$a;-><init>(Lb/rwv;Landroid/content/Context;)V

    .line 288
    .line 289
    .line 290
    new-instance v0, Lb/kx8;

    .line 291
    .line 292
    invoke-direct {v0, v1}, Lb/kx8;-><init>(Lb/rwv$a;)V

    .line 293
    .line 294
    .line 295
    sput-object v0, Lb/nwv;->a:Lb/kx8;

    .line 296
    .line 297
    sget-object v0, Lb/nwv;->b:Ljava/util/concurrent/CountDownLatch;

    .line 298
    .line 299
    invoke-virtual {v0}, Ljava/util/concurrent/CountDownLatch;->countDown()V

    .line 300
    .line 301
    .line 302
    sget-object v0, Lb/cqp;->c:Lb/vzf;

    .line 303
    .line 304
    new-instance v1, Lb/y02;

    .line 305
    .line 306
    const/4 v2, 0x0

    .line 307
    invoke-direct {v1, p0, v2}, Lb/y02;-><init>(Ljava/lang/Object;I)V

    .line 308
    .line 309
    .line 310
    invoke-virtual {v0, v1}, Lb/vpp;->b(Ljava/lang/Runnable;)Lb/f8a;

    .line 311
    .line 312
    .line 313
    return-void
.end method

.method public final t(Lb/yco;)V
    .locals 6
    .param p1    # Lb/yco;
        .annotation build Landroidx/annotation/NonNull;
        .end annotation
    .end param

    .line 1
    iget-object p1, p1, Lb/yco;->a:Ljava/util/EnumMap;

    .line 2
    .line 3
    sget-object v0, Lb/o3e;->h:Lb/o3e;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    new-instance v0, Lb/o3e;

    .line 8
    .line 9
    sget-object v1, Lb/x95;->c:Lb/cwq;

    .line 10
    .line 11
    invoke-static {v1}, Lb/ix0;->a(Lb/cwq;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    check-cast v1, Lb/o61;

    .line 16
    .line 17
    new-instance v2, Lb/i1c$b;

    .line 18
    .line 19
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 20
    .line 21
    .line 22
    invoke-direct {v0, v1, v2}, Lb/i1c;-><init>(Lb/o61;Lb/i1c$b;)V

    .line 23
    .line 24
    .line 25
    const-wide/32 v1, 0xa4cb800

    .line 26
    .line 27
    .line 28
    const-string v3, "APP_VERSION_CHANGED"

    .line 29
    .line 30
    invoke-static {v1, v2, v3}, Lb/i1c$a;->c(JLjava/lang/String;)V

    .line 31
    .line 32
    .line 33
    const-string v3, "CLIENT_ERROR"

    .line 34
    .line 35
    invoke-static {v1, v2, v3}, Lb/i1c$a;->c(JLjava/lang/String;)V

    .line 36
    .line 37
    .line 38
    const-string v3, "SERVER_ERROR"

    .line 39
    .line 40
    invoke-static {v1, v2, v3}, Lb/i1c$a;->c(JLjava/lang/String;)V

    .line 41
    .line 42
    .line 43
    const-string v1, "PHOTO_MODERATION_DIALOG_SHOWN"

    .line 44
    .line 45
    const-wide/32 v2, 0x5265c00

    .line 46
    .line 47
    .line 48
    invoke-static {v2, v3, v1}, Lb/i1c$a;->c(JLjava/lang/String;)V

    .line 49
    .line 50
    .line 51
    sget-object v1, Lb/i1c$a;->a:Ljava/util/HashMap;

    .line 52
    .line 53
    sget-object v2, Lb/i1c$a$a;->a:Lb/i1c$a$a;

    .line 54
    .line 55
    const-string v3, "RATE_US_GIVEN_TIMEOUT"

    .line 56
    .line 57
    invoke-virtual {v1, v3, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    sget-object v1, Lb/i1c$a;->b:Ljava/util/HashMap;

    .line 61
    .line 62
    const-wide/32 v4, 0x6c258c00

    .line 63
    .line 64
    .line 65
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    invoke-virtual {v1, v3, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    sput-object v0, Lb/o3e;->h:Lb/o3e;

    .line 73
    .line 74
    :cond_0
    sget-object v0, Lb/o3e;->h:Lb/o3e;

    .line 75
    .line 76
    sget-object v1, Lb/yco$a;->a:Lb/yco$a;

    .line 77
    .line 78
    invoke-virtual {p1, v1, v0}, Ljava/util/EnumMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    return-void
.end method

.method public final u()V
    .locals 2

    .line 1
    invoke-super {p0}, Lb/x12;->u()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lb/tn;->c:Lb/qn8;

    .line 5
    .line 6
    invoke-virtual {v0}, Lb/qn8;->y()Lb/r0;

    .line 7
    .line 8
    .line 9
    new-instance v0, Lb/v02;

    .line 10
    .line 11
    invoke-direct {v0, p0}, Lb/v02;-><init>(Lcom/hsh/me/hshAppApplication;)V

    .line 12
    .line 13
    .line 14
    sget-boolean v1, Lb/yy7;->b:Z

    .line 15
    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    invoke-virtual {v0}, Lb/v02;->invoke()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    sget-object v1, Lb/yy7;->a:Ljava/util/ArrayList;

    .line 23
    .line 24
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public final w(Lb/p1c;)V
    .locals 1
    .param p1    # Lb/p1c;
        .annotation build Landroidx/annotation/NonNull;
        .end annotation
    .end param

    .line 1
    sget-object v0, Lb/wn6;->d:Lb/wn6;

    .line 2
    .line 3
    invoke-interface {p1, v0}, Lb/p1c;->j(Lb/cu9;)Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    if-nez p1, :cond_1

    .line 8
    .line 9
    sget-object p1, Lb/tn;->c:Lb/qn8;

    .line 10
    .line 11
    iget-object p1, p1, Lb/qn8;->f:Lb/mn8;

    .line 12
    .line 13
    iget-object p1, p1, Lb/mn8;->e:Lb/zqn;

    .line 14
    .line 15
    invoke-interface {p1}, Ljavax/inject/Provider;->get()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    check-cast p1, Lb/gsd;

    .line 20
    .line 21
    invoke-virtual {p1}, Lb/yg3;->c()Z

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    if-eqz p1, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    sget-object p1, Lb/b4f;->a:Lb/b4f;

    .line 29
    .line 30
    sput-object p1, Lb/fy8;->b:Lb/u2;

    .line 31
    .line 32
    return-void

    .line 33
    :cond_1
    :goto_0
    new-instance p1, Lb/nsd;

    .line 34
    .line 35
    sget-object v0, Lb/ema;->h:Lb/on8;

    .line 36
    .line 37
    invoke-virtual {v0}, Lb/on8;->B()Lb/eye;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    invoke-direct {p1, p0, v0}, Lb/nsd;-><init>(Lcom/hsh/me/hshAppApplication;Lb/eye;)V

    .line 42
    .line 43
    .line 44
    sput-object p1, Lb/fy8;->b:Lb/u2;

    .line 45
    .line 46
    return-void
.end method
