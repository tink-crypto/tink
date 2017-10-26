#import "GPBMessage.h"
#import "proto/Common.pbobjc.h"
#import "proto/EciesAeadHkdf.pbobjc.h"
#import "proto/Tink.pbobjc.h"

void TINKAddKey(NSString *keyType, NSUInteger keyId, TINKPBKeyset *keyset);

void TINKAddTinkKey(NSString *keyType,
                    uint32_t keyID,
                    GPBMessage *key,
                    TINKPBKeyStatusType keyStatus,
                    TINKPBKeyData_KeyMaterialType materialType,
                    TINKPBKeyset *keyset);

void TINKAddLegacyKey(NSString *keyType,
                      uint32_t keyID,
                      GPBMessage *key,
                      TINKPBKeyStatusType keyStatus,
                      TINKPBKeyData_KeyMaterialType materialType,
                      TINKPBKeyset *keyset);

void TINKAddRawKey(NSString *keyType,
                   uint32_t keyID,
                   GPBMessage *key,
                   TINKPBKeyStatusType keyStatus,
                   TINKPBKeyData_KeyMaterialType materialType,
                   TINKPBKeyset *keyset);

TINKPBEciesAeadHkdfPrivateKey *TINKGetEciesAesGcmHkdfTestKey(TINKPBEllipticCurveType curveType,
                                                             TINKPBEcPointFormat ecPointFormat,
                                                             TINKPBHashType hashType,
                                                             uint32_t aesGcmKeySize);
