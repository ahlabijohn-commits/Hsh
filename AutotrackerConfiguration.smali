.class public final Lcom/hsh/analytics/autotracker/AutotrackerConfiguration;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/os/Parcelable;


# annotations
.annotation runtime Lkotlin/Metadata;
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/hsh/analytics/autotracker/AutotrackerConfiguration;",
            ">;"
        }
    .end annotation

    .annotation build Lorg/jetbrains/annotations/NotNull;
    .end annotation
.end field


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Lcom/hsh/analytics/autotracker/AutotrackerConfiguration$a;

    invoke-direct {v0}, Lcom/hsh/analytics/autotracker/AutotrackerConfiguration$a;-><init>()V

    sput-object v0, Lcom/hsh/analytics/autotracker/AutotrackerConfiguration;->CREATOR:Landroid/os/Parcelable$Creator;

    return-void
.end method

.method public synthetic constructor <init>(Z)V
    .locals 6

    const/4 v4, 0x1

    const/4 v5, 0x1

    const/4 v2, 0x1

    const/4 v3, 0x1

    move-object v0, p0

    move v1, p1

    .line 1
    invoke-direct/range {v0 .. v5}, Lcom/hsh/analytics/autotracker/AutotrackerConfiguration;-><init>(ZZZZZ)V

    return-void
.end method

.method public constructor <init>(ZZZZZ)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-boolean p1, p0, Lcom/hsh/analytics/autotracker/AutotrackerConfiguration;->a:Z

    .line 4
    iput-boolean p2, p0, Lcom/hsh/analytics/autotracker/AutotrackerConfiguration;->b:Z

    .line 5
    iput-boolean p3, p0, Lcom/hsh/analytics/autotracker/AutotrackerConfiguration;->c:Z

    .line 6
    iput-boolean p4, p0, Lcom/hsh/analytics/autotracker/AutotrackerConfiguration;->d:Z

    .line 7
    iput-boolean p5, p0, Lcom/hsh/analytics/autotracker/AutotrackerConfiguration;->e:Z

    return-void
.end method


# virtual methods
.method public final describeContents()I
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 0
    .param p1    # Landroid/os/Parcel;
        .annotation build Lorg/jetbrains/annotations/NotNull;
        .end annotation
    .end param

    iget-boolean p2, p0, Lcom/hsh/analytics/autotracker/AutotrackerConfiguration;->a:Z

    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    iget-boolean p2, p0, Lcom/hsh/analytics/autotracker/AutotrackerConfiguration;->b:Z

    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    iget-boolean p2, p0, Lcom/hsh/analytics/autotracker/AutotrackerConfiguration;->c:Z

    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    iget-boolean p2, p0, Lcom/hsh/analytics/autotracker/AutotrackerConfiguration;->d:Z

    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    iget-boolean p2, p0, Lcom/hsh/analytics/autotracker/AutotrackerConfiguration;->e:Z

    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    return-void
.end method
