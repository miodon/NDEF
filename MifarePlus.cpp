#include <MifarePlus.h>

// some doc: https://bitbucket.org/tkoskine/arduino-pn532/wiki/NFC_Forum_Type_4_tags
// and: https://bitbucket.org/tkoskine/arduino-pn532/src/f0f0c754964192267621c3ba5ac4efe90fb858de/generic_pn532.adb#lines-366

#define NFC_FORUM_TAG_TYPE_4 ("NFC Forum Type 4")

MifarePlus::MifarePlus(PN532& nfcShield)
{
    nfc = &nfcShield;

}

MifarePlus::~MifarePlus()
{
}

/**
 * ExecuteAPDU - send an APDU to the board, return and check answer
 *
 * @param	send			APDU command
 * @param	sendLength		size of APDU command
 * @param	response		array where to put result of APDU
 * @param	responseLength	pointer to uint8_t where the length of the response 
 *								is returned. Must be size of response array prior to call.
 * @param	expectedResponseLength if > 0 check if responseLength as provided length, if not return false
 * @param 	expectedResponseData  if not null and expectedResponseLength > 0 then check if response 
 *								contains responseLenght otherwise return false.
 */
boolean MifarePlus::executeAPDU(uint8_t *send, uint8_t sendLength, uint8_t *response, uint8_t *responseLength, uint8_t expectedResponseLength , uint8_t *expectedResponseData )
{
		// sending the APDU
		if (!nfc->inDataExchange(send, sendLength, response, responseLength))
		{
			// error while sending APDU
			#ifdef MIFARE_PLUS_DEBUG
			Serial.print(F("Error sending APDU"));
			#endif
			return false;
		}
			
		// check response length if any
		if (expectedResponseLength > 0 && *responseLength != expectedResponseLength ) 
		{
			#ifdef MIFARE_PLUS_DEBUG
			Serial.print(F("Unexpected response length"));
			#endif
			return false;
		}
		
		// check response data if any
		if (expectedResponseLength > 0 && expectedResponseData != NULL) 
		{
			for (int i=0; i<expectedResponseLength; i++)
			{
				if (response[i] != expectedResponseData[i])
				{
					#ifdef MIFARE_PLUS_DEBUG
					Serial.print(F("Unexpected response data"));
					#endif
					return false;					
				}
			}
		}

		return true;
}

NfcTag MifarePlus::read(byte * uid, unsigned int uidLength)
{
		
	uint8_t dataBuffer[255];
	uint8_t dataBufferLength=255;
	
	
	
	uint8_t selectNDEFTagApp[] = {   0x00, // class
							   0xa4, // instruction
							   0x04, // select by name
							   0x00, // first or only occurrence
							   0x07, // length
							   0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, // application name
							   0x00 } ;
	uint8_t selectNDEFTagAppResponse [] = { 0x90, 0x00 } ;

	uint8_t selectNDEFTagFile[] = {   0x00, // class
							   0xa4, // instruction
							   0x00, // select by id
							   0x0c, // first or only occurrence
							   0x02, // length
							   0xe1, 0x03 // capability container
								} ;
	uint8_t selectNDEFTagFileResponse [] = { 0x90, 0x00 } ;

	uint8_t readBinary[] = {   0x00, // class
							   0xb0, 
							   0x00, 
							   0x00, 
							   0x0f // length
								} ;
	
	#ifdef MIFARE_PLUS_DEBUG
	Serial.print(F("MifarePlus read "));
	#endif
	
	// select NDEF APP
	if (!executeAPDU(selectNDEFTagApp, sizeof(selectNDEFTagApp), dataBuffer, &dataBufferLength,  
						sizeof(selectNDEFTagAppResponse), selectNDEFTagAppResponse))
	{
		// error while sending APDU
		#ifdef NDEF_USE_SERIAL
		Serial.print(F("Error selecting ndef app"));
		#endif
		return NfcTag(uid, uidLength, NFC_FORUM_TAG_TYPE_4);
	}							
	
	// reset dataBufferLength
	dataBufferLength = 255;
	
	// select NDEF File capability container
	if (!executeAPDU(selectNDEFTagFile, sizeof(selectNDEFTagFile), dataBuffer, &dataBufferLength,  
						sizeof(selectNDEFTagFileResponse), selectNDEFTagFileResponse ))
	{
		// error while sending APDU
		#ifdef NDEF_USE_SERIAL
		Serial.print(F("Error selecting file capability container"));
		#endif
		return NfcTag(uid, uidLength, NFC_FORUM_TAG_TYPE_4);
	}	

	// reset dataBufferLength
	dataBufferLength = 255;
	
	// read binary, to get real result of previous command and get file name
	if (!executeAPDU(readBinary, sizeof(readBinary), dataBuffer, &dataBufferLength,  
						readBinary[4]+2, NULL))
	{
		// error while sending APDU
		#ifdef NDEF_USE_SERIAL
		Serial.print(F("Error getting file name"));
		#endif
		return NfcTag(uid, uidLength, NFC_FORUM_TAG_TYPE_4);
	}			
	
	// now we should get id of ndef file at dataBuffer[9] and dataBuffer[10]
	// we need to select this file
	// we reuse selectFile APDU and change file id
	selectNDEFTagFile[5] = dataBuffer[9];
	selectNDEFTagFile[6] = dataBuffer[10];
	
	// reset dataBufferLength
	dataBufferLength = 255;		
	
	// execute select NDEF File
	if (!executeAPDU(selectNDEFTagFile, sizeof(selectNDEFTagFile), dataBuffer, &dataBufferLength,  
						sizeof(selectNDEFTagFileResponse),selectNDEFTagFileResponse ))
	{
		// error while sending APDU
		#ifdef NDEF_USE_SERIAL
		Serial.print(F("Error selecting file NDEF"));
		#endif
		return NfcTag(uid, uidLength, NFC_FORUM_TAG_TYPE_4);
	}	

	// reset dataBufferLength
	dataBufferLength = 255;
	
	// read binary, first we only need to get first two bytes to get File Length
	readBinary[4]=2;
	if (!executeAPDU(readBinary, sizeof(readBinary), dataBuffer, &dataBufferLength,  
						readBinary[4]+2, NULL) 
		|| dataBuffer[readBinary[4]+0] != 0x90 || dataBuffer[readBinary[4]+1] != 0x00 ) // we need to check of ok by ourself
	{
		// error while sending APDU
		#ifdef NDEF_USE_SERIAL
		Serial.print(F("Error getting NDEF File Length"));
		#endif
		return NfcTag(uid, uidLength, NFC_FORUM_TAG_TYPE_4);
	}	

	// reset dataBufferLength
	dataBufferLength = 255;
	
	// read binary, first we only need to get first two bytes to get File Length
	readBinary[4]=dataBuffer[1]; // the length we got at previous command
	readBinary[3]=2; 			 // offset, we already got the two first byte of readBinary
	if (!executeAPDU(readBinary, sizeof(readBinary), dataBuffer, &dataBufferLength,  
						readBinary[4]+2, NULL) 
		|| dataBuffer[readBinary[4]+0] != 0x90 || dataBuffer[readBinary[4]+1] != 0x00 ) // we need to check of ok by ourself
	{
		// error while sending APDU
		#ifdef NDEF_USE_SERIAL
		Serial.print(F("Error getting NDEF File Length"));
		#endif
		return NfcTag(uid, uidLength, NFC_FORUM_TAG_TYPE_4);
	}	
				
    NdefMessage ndefMessage = NdefMessage(dataBuffer, readBinary[4]);
    return NfcTag(uid, uidLength, NFC_FORUM_TAG_TYPE_4, ndefMessage);
		

}



/*
 * next function is not yet implemented because I do not have type 4 tag impementing write, 
 * so no way to test. However, this function should nearly the same as the one above. see
 * doc in the head of this file
 */
boolean MifarePlus::write(NdefMessage& m, byte * uid, unsigned int uidLength)
{
#ifdef NDEF_USE_SERIAL
    Serial.println(F("ERROR: Write to MifarePlus is not yet implemented."));
#endif

    return false;
}


/*
 * next function is not yet implemented because I do not have type 4 tag impementing write, 
 * so no way to test. However, this function should nearly the same as the one above. see
 * doc in the head of this file
 */
boolean MifarePlus::clean()
{
#ifdef NDEF_USE_SERIAL
    Serial.println(F("ERROR: Write to MifarePlus is not yet implemented."));
#endif
    return false;
}
