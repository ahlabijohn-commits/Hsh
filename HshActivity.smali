.class public final Lcom/hsh/me/android/hshActivity;
.super Lb/pvj;
.source "SourceFile"

# interfaces
.implements Lb/gig$a;


# annotations
.annotation runtime Lkotlin/Metadata;
.end annotation


# static fields
.field public static final O:Lcom/hsh/smartresources/b$a;
    .annotation build Lorg/jetbrains/annotations/NotNull;
    .end annotation
.end field

.field public static final P:Lcom/hsh/smartresources/b$a;
    .annotation build Lorg/jetbrains/annotations/NotNull;
    .end annotation
.end field

.field public static final Q:Lb/okg;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lb/okg<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .annotation build Lorg/jetbrains/annotations/NotNull;
    .end annotation
.end field


# instance fields
.field public final K:Lb/okg;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lb/okg<",
            "Lb/gig;",
            ">;"
        }
    .end annotation

    .annotation build Lorg/jetbrains/annotations/NotNull;
    .end annotation
.end field

.field public N:Lb/f8a;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/hsh/smartresources/b$a;

    .line 2
    .line 3
    const/16 v1, 0xbe

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lcom/hsh/smartresources/b$a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lcom/hsh/me/android/hshActivity;->O:Lcom/hsh/smartresources/b$a;

    .line 9
    .line 10
    new-instance v0, Lcom/hsh/smartresources/b$a;

    .line 11
    .line 12
    invoke-direct {v0, v1}, Lcom/hsh/smartresources/b$a;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lcom/hsh/me/android/hshActivity;->P:Lcom/hsh/smartresources/b$a;

    .line 16
    .line 17
    new-instance v0, Lb/rx1;

    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    invoke-direct {v0, v1}, Lb/rx1;-><init>(I)V

    .line 21
    .line 22
    .line 23
    invoke-static {v0}, Lb/umg;->b(Lkotlin/jvm/functions/Function0;)Lb/okg;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    sput-object v0, Lcom/hsh/me/android/hshActivity;->Q:Lb/okg;

    .line 28
    .line 29
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Lb/pvj;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lb/dh;

    .line 5
    .line 6
    const/4 v1, 0x3

    .line 7
    invoke-direct {v0, p0, v1}, Lb/dh;-><init>(Ljava/lang/Object;I)V

    .line 8
    .line 9
    .line 10
    invoke-static {v0}, Lb/umg;->b(Lkotlin/jvm/functions/Function0;)Lb/okg;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iput-object v0, p0, Lcom/hsh/me/android/hshActivity;->K:Lb/okg;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final E2(Landroid/os/Bundle;)V
    .locals 3

    .line 1
    sget-object v0, Lb/r22;->a:[Lb/r22;

    .line 2
    .line 3
    sget-object v0, Lb/tn;->c:Lb/qn8;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const/4 v0, 0x0

    .line 9
    :goto_0
    invoke-virtual {v0}, Lb/qn8;->C()Lb/h61;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    sget-wide v1, Lb/u03;->k:J

    .line 14
    .line 15
    invoke-interface {v0, v1, v2}, Lb/h61;->c(J)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0}, Lcom/hsh/me/ui/b;->getIntent()Landroid/content/Intent;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    const-string v1, "getIntent(...)"

    .line 23
    .line 24
    invoke-static {v0, v1}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullExpressionValue(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    sget-object v0, Lb/eit;->a:Lb/eit$a;

    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    sget-object v1, Lcom/hsh/me/android/hshActivity;->Q:Lb/okg;

    .line 33
    .line 34
    invoke-interface {v1}, Lb/okg;->getValue()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    check-cast v1, Ljava/lang/String;

    .line 39
    .line 40
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 41
    .line 42
    .line 43
    invoke-super {p0, p1}, Lcom/hsh/me/ui/b;->E2(Landroid/os/Bundle;)V

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public final F2(Landroid/os/Bundle;)V
    .locals 3

    .line 1
    invoke-super {p0, p1}, Lcom/hsh/me/ui/b;->F2(Landroid/os/Bundle;)V

    .line 2
    .line 3
    .line 4
    const p1, 0x7f0d01b9

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0, p1}, Lcom/hsh/me/ui/b;->setContentView(I)V

    .line 8
    .line 9
    .line 10
    const p1, 0x7f0a0d65

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lb/ps0;->findViewById(I)Landroid/view/View;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    check-cast p1, Lcom/airbnb/lottie/LottieAnimationView;

    .line 18
    .line 19
    if-eqz p1, :cond_2

    .line 20
    .line 21
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    sget-object v1, Lcom/hsh/me/android/hshActivity;->P:Lcom/hsh/smartresources/b$a;

    .line 28
    .line 29
    invoke-static {v1, p0}, Lcom/hsh/smartresources/a;->l(Lcom/hsh/smartresources/b;Landroid/content/Context;)I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    iput v1, v0, Landroid/view/ViewGroup$LayoutParams;->width:I

    .line 34
    .line 35
    sget-object v1, Lcom/hsh/me/android/hshActivity;->O:Lcom/hsh/smartresources/b$a;

    .line 36
    .line 37
    invoke-static {v1, p0}, Lcom/hsh/smartresources/a;->l(Lcom/hsh/smartresources/b;Landroid/content/Context;)I

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    iput v1, v0, Landroid/view/ViewGroup$LayoutParams;->height:I

    .line 42
    .line 43
    invoke-virtual {p1, v0}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 44
    .line 45
    .line 46
    :cond_0
    new-instance v0, Lb/ux1;

    .line 47
    .line 48
    invoke-direct {v0, p0, p1}, Lb/ux1;-><init>(Lcom/hsh/me/android/hshActivity;Lcom/airbnb/lottie/LottieAnimationView;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p1}, Lcom/airbnb/lottie/LottieAnimationView;->getComposition()Lb/ukh;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    if-eqz v1, :cond_1

    .line 56
    .line 57
    invoke-virtual {v0}, Lb/ux1;->a()V

    .line 58
    .line 59
    .line 60
    :cond_1
    iget-object p1, p1, Lcom/airbnb/lottie/LottieAnimationView;->l:Ljava/util/HashSet;

    .line 61
    .line 62
    invoke-virtual {p1, v0}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    :cond_2
    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    invoke-virtual {p1}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    new-instance v0, Lb/vx1;

    .line 74
    .line 75
    invoke-direct {v0, p0}, Lb/vx1;-><init>(Lcom/hsh/me/android/hshActivity;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {p1, v0}, Landroid/view/View;->setOnApplyWindowInsetsListener(Landroid/view/View$OnApplyWindowInsetsListener;)V

    .line 79
    .line 80
    .line 81
    const/4 p1, 0x0

    .line 82
    sput-boolean p1, Lb/x12;->o:Z

    .line 83
    .line 84
    invoke-virtual {p0}, Lcom/hsh/me/ui/b;->getIntent()Landroid/content/Intent;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    invoke-virtual {p1}, Landroid/content/Intent;->getData()Landroid/net/Uri;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    invoke-virtual {p1}, Landroid/content/Intent;->getFlags()I

    .line 93
    .line 94
    .line 95
    move-result v1

    .line 96
    const/high16 v2, 0x400000

    .line 97
    .line 98
    and-int/2addr v1, v2

    .line 99
    if-eqz v1, :cond_4

    .line 100
    .line 101
    if-nez v0, :cond_4

    .line 102
    .line 103
    invoke-virtual {p1}, Landroid/content/Intent;->getFlags()I

    .line 104
    .line 105
    .line 106
    move-result v0

    .line 107
    const/high16 v1, 0x10000000

    .line 108
    .line 109
    and-int/2addr v0, v1

    .line 110
    if-eqz v0, :cond_3

    .line 111
    .line 112
    invoke-virtual {p1}, Landroid/content/Intent;->getFlags()I

    .line 113
    .line 114
    .line 115
    move-result v0

    .line 116
    const v1, 0x8000

    .line 117
    .line 118
    .line 119
    and-int/2addr v0, v1

    .line 120
    if-nez v0, :cond_4

    .line 121
    .line 122
    :cond_3
    sget-object p1, Lb/eit;->a:Lb/eit$a;

    .line 123
    .line 124
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 125
    .line 126
    .line 127
    invoke-virtual {p0}, Lcom/hsh/me/android/hshActivity;->finish()V

    .line 128
    .line 129
    .line 130
    return-void

    .line 131
    :cond_4
    invoke-static {p0}, Lb/s52;->a(Lb/pvj;)V

    .line 132
    .line 133
    .line 134
    sget-object v0, Lb/ucb;->F6:Lb/ucb;

    .line 135
    .line 136
    const/4 v1, 0x0

    .line 137
    invoke-virtual {v0, v1}, Lb/ucb;->d(Ljava/lang/Object;)I

    .line 138
    .line 139
    .line 140
    sget-object v0, Lb/tn;->c:Lb/qn8;

    .line 141
    .line 142
    if-eqz v0, :cond_5

    .line 143
    .line 144
    move-object v1, v0

    .line 145
    :cond_5
    invoke-virtual {v1}, Lb/qn8;->X()Lb/giu;

    .line 146
    .line 147
    .line 148
    move-result-object v0

    .line 149
    invoke-interface {v0}, Lb/giu;->f()V

    .line 150
    .line 151
    .line 152
    invoke-virtual {p0, p1}, Lcom/hsh/me/android/hshActivity;->Q2(Landroid/content/Intent;)V

    .line 153
    .line 154
    .line 155
    return-void
.end method

.method public final Q2(Landroid/content/Intent;)V
    .locals 3

    .line 1
    const-string v0, "exit"

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {p1, v0, v1}, Landroid/content/Intent;->getBooleanExtra(Ljava/lang/String;Z)Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {p0}, Lcom/hsh/me/android/hshActivity;->finish()V

    .line 11
    .line 12
    .line 13
    new-instance p1, Lb/xx1;

    .line 14
    .line 15
    const-string v0, "DelayedExit"

    .line 16
    .line 17
    invoke-direct {p1, v0}, Ljava/lang/Thread;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p1}, Ljava/lang/Thread;->start()V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :cond_0
    sget-object v0, Lb/cqp;->c:Lb/vzf;

    .line 25
    .line 26
    new-instance v1, Lb/qx1;

    .line 27
    .line 28
    const/4 v2, 0x0

    .line 29
    invoke-direct {v1, v2, p0, p1}, Lb/qx1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0, v1}, Lb/vpp;->b(Ljava/lang/Runnable;)Lb/f8a;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    iput-object p1, p0, Lcom/hsh/me/android/hshActivity;->N:Lb/f8a;

    .line 37
    .line 38
    return-void
.end method

.method public final f()V
    .locals 2

    .line 1
    new-instance v0, Lb/wx1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1}, Lb/wx1;-><init>(Ljava/lang/Object;I)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0, v0}, Landroid/app/Activity;->runOnUiThread(Ljava/lang/Runnable;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final finish()V
    .locals 1

    .line 1
    invoke-super {p0}, Lcom/hsh/me/ui/b;->finish()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lb/r22;->a:[Lb/r22;

    .line 5
    .line 6
    return-void
.end method

.method public final j2()Z
    .locals 1

    .line 1
    const/4 v0, 0x0

    return v0
.end method

.method public final k(Ljava/lang/String;)V
    .locals 2

    .line 1
    new-instance v0, Lb/tx1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1, p0, p1}, Lb/tx1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0, v0}, Landroid/app/Activity;->runOnUiThread(Ljava/lang/Runnable;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final n()V
    .locals 2

    .line 1
    new-instance v0, Lb/sx1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1}, Lb/sx1;-><init>(Ljava/lang/Object;I)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0, v0}, Landroid/app/Activity;->runOnUiThread(Ljava/lang/Runnable;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final onDestroy()V
    .locals 3

    .line 1
    invoke-super {p0}, Lcom/hsh/me/ui/b;->onDestroy()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lb/tn;->c:Lb/qn8;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    move-object v0, v1

    .line 11
    :goto_0
    invoke-virtual {v0}, Lb/qn8;->C()Lb/h61;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-interface {v0}, Lb/h61;->b()V

    .line 16
    .line 17
    .line 18
    iget-object v0, p0, Lcom/hsh/me/android/hshActivity;->K:Lb/okg;

    .line 19
    .line 20
    invoke-interface {v0}, Lb/okg;->isInitialized()Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_1

    .line 25
    .line 26
    invoke-interface {v0}, Lb/okg;->getValue()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    check-cast v0, Lb/gig;

    .line 31
    .line 32
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 33
    .line 34
    .line 35
    sget-object v2, Lb/ucb;->b0:Lb/ucb;

    .line 36
    .line 37
    invoke-virtual {v2, v0}, Lb/ucb;->g(Lb/a23;)V

    .line 38
    .line 39
    .line 40
    sget-object v2, Lb/ucb;->c0:Lb/ucb;

    .line 41
    .line 42
    invoke-virtual {v2, v0}, Lb/ucb;->g(Lb/a23;)V

    .line 43
    .line 44
    .line 45
    :cond_1
    iget-object v0, p0, Lcom/hsh/me/android/hshActivity;->N:Lb/f8a;

    .line 46
    .line 47
    if-eqz v0, :cond_2

    .line 48
    .line 49
    invoke-interface {v0}, Lb/f8a;->dispose()V

    .line 50
    .line 51
    .line 52
    :cond_2
    iput-object v1, p0, Lcom/hsh/me/android/hshActivity;->N:Lb/f8a;

    .line 53
    .line 54
    return-void
.end method

.method public final onNewIntent(Landroid/content/Intent;)V
    .locals 2
    .param p1    # Landroid/content/Intent;
        .annotation build Lorg/jetbrains/annotations/NotNull;
        .end annotation
    .end param

    .line 1
    sget-object v0, Lb/eit;->a:Lb/eit$a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    sget-object v1, Lcom/hsh/me/android/hshActivity;->Q:Lb/okg;

    .line 7
    .line 8
    invoke-interface {v1}, Lb/okg;->getValue()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    check-cast v1, Ljava/lang/String;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    invoke-super {p0, p1}, Lcom/hsh/me/ui/b;->onNewIntent(Landroid/content/Intent;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Landroid/app/Activity;->isTaskRoot()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    invoke-virtual {p0, p1}, Lcom/hsh/me/android/hshActivity;->Q2(Landroid/content/Intent;)V

    .line 27
    .line 28
    .line 29
    :cond_0
    return-void
.end method

.method public final z2()Lb/y2k;
    .locals 1
    .annotation build Lorg/jetbrains/annotations/NotNull;
    .end annotation

    .line 1
    sget-object v0, Lb/y2k;->d:Lb/y2k;

    .line 2
    .line 3
    return-object v0
.end method
