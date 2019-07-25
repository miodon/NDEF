#ifndef MifarePlus_h
#define MifarePlus_h

#include <PN532.h>
#include <NfcTag.h>
#include <Ndef.h>

class MifarePlus
{
    public:
        MifarePlus(PN532& nfcShield);
        ~MifarePlus();
        NfcTag read(byte *uid, unsigned int uidLength);
        boolean write(NdefMessage& ndefMessage, byte *uid, unsigned int uidLength);
        boolean clean();
    private:
        PN532* nfc;
        boolean isUnformatted();
		boolean executeAPDU(uint8_t *send, uint8_t sendLength, uint8_t *response, uint8_t *responseLength, uint8_t expectedResponseLength = 0, uint8_t *expectedResponseData = NULL);
};

#endif
