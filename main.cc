#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>

#include <QtGui/QApplication>
#include <QtGui/QGraphicsScene>
#include "rpcui.h"
#include "action.h"

#define IP6_ADDR_SIZE 40
#define MIN(a,b) (a<b?a:b)
#define MAXIF 4

typedef struct net_if_id_ {
    char name[8];
    int id;
} net_if_id_t;

static net_if_id_t net_if_id[MAXIF];

#define SIGNATURE "MUMU"
#define IS_LINK_LOCAL_IP6(addr) ((((char*)addr)[0] & 0xff) == 0xfe && ((((char*)addr)[1] & 0xff) & (1 << 7)) != 0)

struct addrinfo hints;
struct sockaddr_in6 peerIp;
struct ifaddrs *ifap;

/* arg is something like c3 where c is 1100 for set and 3 is 0011 for clear */
int8_t get_mask(char *arg)
{
    uint8_t a = 0;
    if (strlen(arg) < 2) return -1;
    if (arg[0] > 'a') arg[0] -= ('a' - 'A');
    if (arg[1] > 'a') arg[1] -= ('a' - 'A');

    if (arg[1] >= '0' && arg[1] <= '9') {
        a |= arg[1] - '0';
    } else if (arg[1] >= 'A' && arg[1] <= 'F') {
        a |= (arg[1] - 'A' + 10);
    } else {
        return -1;
    }
    if (arg[0] >= '0' && arg[0] <= '9') {
        a |= (arg[0] - '0') << 4;
    } else if (arg[0] >= 'A' && arg[0] <= 'F') {
        a |= (arg[0] - 'A' + 10) << 4;
    } else {
        return -1;
    }

    if (((a & 0xf) & (a >> 4)) != 0) {
        /* cannot have same bit with 1 for set and 1 for clear */
        return -1;
    }
    return a;
}


Ui_PwrDialog pwrDialog;
struct in6_addr peer_ip;

int getAction::send_msg(void)
{
    int i, size;
    socklen_t len;


    for (i = 0; i < 3; i++) {
        memcpy(&peerIp.sin6_addr, &peer_ip, sizeof(peerIp.sin6_addr));
        printf("Send %d bytes!\n",
            (i = sendto(sock, &msg, sizeof(msg), 0, (const sockaddr*)&peerIp, sizeof(struct sockaddr_in6))));
        if (i < 0) {
            pwrDialog.lineEditStat->setText("Send FAIL");
            perror("sendto");
            return FALSE;
        }

        len = sizeof(struct sockaddr_in6);
        memcpy(&peerIp.sin6_addr, &((struct sockaddr_in6*)(res->ai_addr))->sin6_addr, sizeof(peerIp.sin6_addr));
        size = recvfrom(sock, &msg, sizeof(msg), 0, (struct sockaddr *)&peerIp, &len);
        printf("got current mask %02x size %d\n", msg.set_clear_mask & 0xf, size);
        if (size > 0) {
            break;
        }
        if (size < 0 && i >=2) {
            perror("recv");
            pwrDialog.lineEditStat->setText("Recv FAIL");
            return FALSE;
        }
    }
}

void getAction::init(void)
{
    is_connected = 0;
    msg = {.sig = {'M', 'U', 'M', 'U'}, .ver = 1, .set_clear_mask = 0, .zero = 0 };
}

void getAction::pwr1StateChanged(int state)
{
    if (!is_connected) return;
    printf("pwr1 state %d\n", state);
    if (state == Qt::Checked) {
        msg.set_clear_mask = 1 << 4;
    } else {
        msg.set_clear_mask = 1;
    }
    if (send_msg()) {
        printf("ok!\n");
    }
}

void getAction::pwr2StateChanged(int state)
{
    if (!is_connected) return;
    printf("pwr2 state %d\n", state);
    if (state == Qt::Checked) {
        msg.set_clear_mask = 2 << 4;
    } else {
        msg.set_clear_mask = 2;
    }
    if (send_msg()) {
        printf("ok!\n");
    }
}

void getAction::pwr3StateChanged(int state)
{
    if (!is_connected) return;
    printf("pwr3 state %d\n", state);
    if (state == Qt::Checked) {
        msg.set_clear_mask = 4 << 4;
    } else {
        msg.set_clear_mask = 4;
    }
    if (send_msg()) {
        printf("ok!\n");
    }
}

void getAction::pwr4StateChanged(int state)
{
    if (!is_connected) return;
    printf("pwr4 state %d\n", state);
    if (state == Qt::Checked) {
        msg.set_clear_mask = 8 << 4;
    } else {
        msg.set_clear_mask = 8;
    }
    if (send_msg()) {
        printf("ok!\n");
    }
}

void getAction::enterPressed(void)
{
    printf("enter..\n");
}

void getAction::onQuit(void)
{
    freeaddrinfo(res);
    close(sock);
    freeifaddrs(ifap);
    printf("Bye!\n");
}

void inline qstring_to_char(QString str, char *dest)
{
    int i;
    QChar *qch = str.data();;
    for (i = 0; dest[i]=qch[i].toAscii(); i++);
}

void getAction::connectPressed(void)
{
    char addr_str[IP6_ADDR_SIZE];
    int i,s, ifindex, size;
    socklen_t len;
    struct ifaddrs  *it;
    struct timeval tv;
    struct in6_addr local_ip;
    char addr[IP6_ADDR_SIZE], service[] = "4000", dev_name[8];
    struct sockaddr_in6 *ptr;

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    if (0 == is_connected) {
        pwrDialog.connectButton->setEnabled(FALSE);
        qstring_to_char(pwrDialog.comboBox->currentText(),dev_name);
        printf("ifname %s pid %d\n", dev_name, getpid());
        for (i = 0; net_if_id[i].id != 0; i++) {
            if (0 == strcmp(net_if_id[i].name, dev_name)) {
                ifindex = net_if_id[i].id;
                break;
            }
        }
        /* got peerip from lineEdit box and convert to struct in6_addr */
        pwrDialog.lineEdit->setEnabled(FALSE);
        qstring_to_char(pwrDialog.lineEdit->text(),addr_str);
        printf("peer ip %s\n", addr_str);
        inet_pton(AF_INET6, addr_str, (void*)&peer_ip);
        for (it = ifap; it; it=it->ifa_next) {
            if (0 == strcmp(it->ifa_name,dev_name)) {
                if (it->ifa_addr->sa_family != AF_INET6) continue;
                if (IS_LINK_LOCAL_IP6(peer_ip.s6_addr) !=
                        IS_LINK_LOCAL_IP6((((struct sockaddr_in6*)((it->ifa_addr)))->sin6_addr.s6_addr))) continue;
                memcpy(&local_ip,((struct sockaddr_in6*)(it->ifa_addr))->sin6_addr.s6_addr,sizeof(local_ip));
                break;
            }
        }
        /* set addr_str for getaddrinfo() and print current values */
        printf("dev %s got addr %s sock %d\n", dev_name, inet_ntop(AF_INET6, (void*)&local_ip, addr_str, sizeof(addr_str)), sock);

        s = getaddrinfo(addr_str, service, &hints, &res);
        if (s != 0) {
            pwrDialog.lineEditStat->setText("Address get FAIL");
            perror("address error");
            res = NULL;
            goto exit;
        }

        sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock < 0) {
            pwrDialog.lineEditStat->setText("socket FAIL");
            perror("socket");
            goto exit;
        }

        ((struct sockaddr_in6*)(res->ai_addr))->sin6_scope_id = ifindex;
        printf("ifindex %d addr %s\n", ifindex, inet_ntop(AF_INET6, &(((struct sockaddr_in6*)(res->ai_addr))->sin6_addr),
                    addr_str, sizeof(addr_str)));
        if (bind(sock, res->ai_addr, res->ai_addrlen)) {
            pwrDialog.lineEditStat->setText("bind FAIL");
            perror("bind");
            goto exit;
        }

        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
            pwrDialog.lineEditStat->setText("Socket timeout set FAIL");
            perror("Error");
            goto exit;
        }

        ptr = (struct sockaddr_in6*)res->ai_addr;
        peerIp.sin6_family = ptr->sin6_family;
        peerIp.sin6_port = ptr->sin6_port;
        peerIp.sin6_flowinfo = ptr->sin6_flowinfo;
        peerIp.sin6_scope_id = ifindex;
        printf("connect..\n");
        msg.set_clear_mask = 0; /* we should only query state */

        for (i = 0; i < 3; i++) {
            memcpy(&peerIp.sin6_addr, &peer_ip, sizeof(peerIp.sin6_addr));
            printf("Send %d bytes!\n",
                (s = sendto(sock, &msg, sizeof(msg), 0, (const sockaddr*)&peerIp, sizeof(struct sockaddr_in6))));
            if (s < 0) {
                pwrDialog.lineEditStat->setText("Send FAIL");
                perror("sendto");
                goto exit;
            }

            len = sizeof(struct sockaddr_in6);
            memcpy(&peerIp.sin6_addr, &((struct sockaddr_in6*)(res->ai_addr))->sin6_addr, sizeof(peerIp.sin6_addr));
            size = recvfrom(sock, &msg, sizeof(msg), 0, (struct sockaddr *)&peerIp, &len);
            printf("got current mask %02x size %d\n", msg.set_clear_mask & 0xf, size);
            if (size > 0) {
                break;
            }
            msg.set_clear_mask = 0; /* we should only query state */
            if (size < 0 && i >= 2) {
                perror("recv");
                pwrDialog.lineEditStat->setText("Recv FAIL");
                goto exit;
            }
        }

        printf("%s: size = %d\n", __func__, size);
        pwrDialog.connectButton->setText("Disconnect");
        ((QWidget*)(pwrDialog.checkBoxPwr1))->setEnabled(TRUE);
        ((QWidget*)(pwrDialog.checkBoxPwr2))->setEnabled(TRUE);
        ((QWidget*)(pwrDialog.checkBoxPwr3))->setEnabled(TRUE);
        ((QWidget*)(pwrDialog.checkBoxPwr4))->setEnabled(TRUE);
        if ((msg.set_clear_mask & 0xf) & 1) {
            pwrDialog.checkBoxPwr1->setCheckState(Qt::Checked);
        } else {
            pwrDialog.checkBoxPwr1->setCheckState(Qt::Unchecked);
        }
        if ((msg.set_clear_mask & 0xf) & 2) {
            pwrDialog.checkBoxPwr2->setCheckState(Qt::Checked);
        } else {
            pwrDialog.checkBoxPwr2->setCheckState(Qt::Unchecked);
        }
        if ((msg.set_clear_mask & 0xf) & 4) {
            pwrDialog.checkBoxPwr3->setCheckState(Qt::Checked);
        } else {
            pwrDialog.checkBoxPwr3->setCheckState(Qt::Unchecked);
        }
        if ((msg.set_clear_mask & 0xf) & 8) {
            pwrDialog.checkBoxPwr4->setCheckState(Qt::Checked);
        } else {
            pwrDialog.checkBoxPwr4->setCheckState(Qt::Unchecked);
        }
        pwrDialog.connectButton->setEnabled(TRUE);
        pwrDialog.lineEditStat->setText("Connected");
        is_connected = 1;
    } else {
            pwrDialog.lineEditStat->setText("Not Connected");
exit:
        is_connected = 0;
        pwrDialog.lineEdit->setEnabled(TRUE);
        pwrDialog.connectButton->setEnabled(TRUE);
        pwrDialog.connectButton->setText("Connect!");
        close(sock);
        if (NULL != res) {
            freeaddrinfo(res);
            res = NULL;
        }
        ((QWidget*)(pwrDialog.checkBoxPwr1))->setEnabled(FALSE);
        ((QWidget*)(pwrDialog.checkBoxPwr2))->setEnabled(FALSE);
        ((QWidget*)(pwrDialog.checkBoxPwr3))->setEnabled(FALSE);
        ((QWidget*)(pwrDialog.checkBoxPwr4))->setEnabled(FALSE);
    }
}

int main(int argc, char *argv[])
{
    struct ifreq ifrq;
    int i,j = 0,s;
    QApplication a(argc,argv);
    QDialog dialog;
    getAction my_actions;
    char addr[IP6_ADDR_SIZE], service[] = "4000";
    struct ifaddrs *it;
    int sock;
    struct addrinfo *res;

    my_actions.init();

    pwrDialog.setupUi(&dialog);

    if (getifaddrs(&ifap) != 0)
        perror("getifaddrs");

    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = 0;
    hints.ai_protocol = IPPROTO_UDP;

    strcpy(addr, "::1");
    printf("pid %d\n", getpid());

    s = getaddrinfo(addr, service, &hints, &res);
    if (s != 0) {
        perror("getaddrinfo");
        abort();
    }

    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    for (i = 0, it = ifap; i < MAXIF && it; it = it->ifa_next) {
        QString qstr;
        s = 0; /* used to go to next if */
        for (j = 0; j < i; j++) {
            if (0 == strcmp(net_if_id[j].name, it->ifa_name)) {
                s = 1; /* if already added */
                break;
            }
        }
        if (s) continue;
        strcpy(net_if_id[i].name, it->ifa_name);
        strcpy(ifrq.ifr_name, it->ifa_name);
        if (ioctl(sock,SIOCGIFINDEX,&ifrq, sizeof(ifrq)) != 0) {
            continue;
        }
        qstr = QString(it->ifa_name);
        net_if_id[i].id = ifrq.ifr_ifindex;
        i++;
        pwrDialog.comboBox->addItem(qstr);
    }
    close(sock);
    freeaddrinfo(res);

    dialog.show();
    QObject::connect(pwrDialog.checkBoxPwr1, SIGNAL(stateChanged(int)), &my_actions, SLOT(pwr1StateChanged(int)));
    QObject::connect(pwrDialog.checkBoxPwr2, SIGNAL(stateChanged(int)), &my_actions, SLOT(pwr2StateChanged(int)));
    QObject::connect(pwrDialog.checkBoxPwr3, SIGNAL(stateChanged(int)), &my_actions, SLOT(pwr3StateChanged(int)));
    QObject::connect(pwrDialog.checkBoxPwr4, SIGNAL(stateChanged(int)), &my_actions, SLOT(pwr4StateChanged(int)));
    QObject::connect(pwrDialog.connectButton, SIGNAL(clicked()), &my_actions, SLOT(connectPressed()));
    QObject::connect(&a, SIGNAL(lastWindowClosed()), &my_actions, SLOT(onQuit()));
    return a.exec();
}

