#ifndef __ACTION_H__
#define __ACTION_H__

#include <QtCore/QObject>
#include <stdint.h>

typedef struct msg_ {
    char sig[4]; /* "MUMU" */
    uint16_t ver;
    uint8_t set_clear_mask;
    uint8_t zero;
} __attribute__((packed)) msg_t;

class getAction : public QObject
{
    Q_OBJECT
    public slots:
        void enterPressed(void);
        void connectPressed(void);
        void pwr1StateChanged(int state);
        void pwr2StateChanged(int state);
        void pwr3StateChanged(int state);
        void pwr4StateChanged(int state);
        void onQuit(void);
        void init(void);
        
    private:
        int send_msg(void);
        msg_t msg;
        int is_connected;
        int sock;
        struct addrinfo *res;
};

#endif
