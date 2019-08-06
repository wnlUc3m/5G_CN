import random
from Security import *
import pandas as pd
from HssUeContext import HssUeContext

from random import _urandom as urandom
from struct import pack, unpack
from binascii import hexlify, unhexlify
from pycrate_mobile.TS24008_IE import PLMN

try:
    from CryptoMobile.Milenage import *
    from CryptoMobile.CM import SNOW3G
except ImportError as error:
    print "CryptoMobile library is required for using Milenage algorithms"
    raise error

class Hss:

    # TODO: Add DAO + abstract factory to get access to a real database
    #DB_FILENAME = "authentication/users_db_backup.txt"
    DB_FILENAME = "/home/user/sdn_based_epc/authentication/users_db.txt"

    def __init__(self):
        self.algorithm_handler = {}
        self.algorithm_handler['xor'] = "generate_authentication_info_answer_xor"
        self.algorithm_handler['milenage'] = "generate_authentication_info_answer_milenage"
        
        # TODO: mover para que se pueda coger de un archivo de configuracion
        self.authentication_algorithm = "milenage"

        # map <imsi, HssUeContext> 
        self.imsi_to_uecontext = {}
        self.users_caching()

        #self.plmn = '\x02\xf8\x39'
        self.plmn = chr(int("00000010",2)) + chr(int("11111000",2)) + chr(int("00111001",2))
        self.mcc = 208
        self.mnc = 93

    def users_caching(self):
        # TODO: limit number of "users" to read when database is too large
        rows_to_extract = 3
        data = pd.read_csv(Hss.DB_FILENAME, sep=" ", header=0, nrows=rows_to_extract, dtype=str)
        for user_name in data['NAME'].values:
            concrete_data = data[data['NAME'] == user_name]
            imsi = str(concrete_data['IMSI'].iloc[0])
            key = concrete_data['KEY'].iloc[0]
            op = concrete_data['OP'].iloc[0]
            amf = str(concrete_data['AMF'].iloc[0])
            sqn = concrete_data['SQN'].iloc[0]
            print "      >> Added %s %s" % (user_name, imsi)
            self.imsi_to_uecontext[imsi] = HssUeContext(user_name, imsi, key, op, amf, sqn)


    def set_algorithm(self, algorithm):
        self.authentication_algorithm = algorithm

    def generate_authentication_information_answer(self, imsi):
        method = getattr(self, self.algorithm_handler[self.authentication_algorithm])
        return method(imsi)
        '''
        try:
            method = getattr(self, self.algorithm_handler[self.authentication_algorithm])
            return method(imsi)
        except Exception as e:
            print imsi
            print e
            print "%s algorithm is not supported. Only Milenage or XOR algorithms are supported " % self.authentication_algorithm
            # TODO: retornar un mensaje de error
        '''

    # Produces 4G authentication vector using CryptoMobile lib for a given IMSI and network MCC/MNC
    #   Requests to the DB for the authentication key of an specific IMSI
    #   Returns:
    #     - k_asme; autn, random_val, xres
    #   Acknowledgments: libmich
    def generate_authentication_info_answer_milenage(self, imsi, RAND=None):

        serving_network_id = PLMN(val=self.plmn).to_bytes()
        if len(serving_network_id) != 3:
            print "Invalid SN_ID %s" % hexlify(serving_network_id).decode('ascii')

        # Get provided subscriber key (k), authentication management field (amf) and operator variant configuration field (op) if imsi is found
        K, AMF, OP, SQN, result = self.check_key_amf_op(imsi)
        
        # Pack SQN from integer to buffer
        SQNb = b'\0\0' + pack('>I', int(SQN))

        # Generate challenge
        if RAND is None or len(RAND) != 16:
            RAND = urandom(16)
        self.imsi_to_uecontext[imsi].set_rand(RAND)

        # Compute milenage functions
        milenage = Milenage(OP)
        XRES, CK, IK, AK = milenage.f2345(K, RAND, OP)
        MAC_A = milenage.f1(K, RAND, SQNb, AMF)
        SQN_X_AK = xor_buf(SQNb, AK)
        AUTN = SQN_X_AK + AMF + MAC_A
        K_ASME = conv_A2(CK, IK, serving_network_id, SQN_X_AK)
        # Store generated information
        self.imsi_to_uecontext[imsi].set_ik(IK)
        self.imsi_to_uecontext[imsi].set_ck(CK)
        self.imsi_to_uecontext[imsi].set_ak(AK)
        self.imsi_to_uecontext[imsi].set_xres(XRES)
        self.imsi_to_uecontext[imsi].set_autn(AUTN)

        print "\t [INFO] Generated Authentication vector for %s" % (imsi)
        return RAND, XRES, AUTN, K_ASME 

    def generate_authentication_info_answer_xor(self, imsi, k_asme, autn, random_val, xres):
        # TODO: not implemented
        print "XOR auth not implemented"

    # Return NAS keys (k_nas_int and k_nas_enc) using K_ASME, the identifier of the algorithm and the distinguisher
    #   Input: K_ASME and the algorithm identifiers and distinguisers for int an enc keys
    def generate_k_nas(self, k_asme, int_alg_id, int_alg_dis, enc_alg_id, enc_alg_dis):
        k_nas_int = conv_A7(k_asme, int_alg_id, int_alg_dis)[16:32]
        k_nas_enc = conv_A7(k_asme, enc_alg_id, enc_alg_dis)[16:32]

        return k_nas_int, k_nas_enc

    def generate_k_enb(self, k_asme, ul_nas_cnt):
        return conv_A3(k_asme, ul_nas_cnt)

    def check_key_amf_op(self, imsi):
        try:
            user_key = self.imsi_to_uecontext[imsi].get_key()
            user_amf = self.imsi_to_uecontext[imsi].get_amf()
            user_op = self.imsi_to_uecontext[imsi].get_op()
            user_sqn = self.imsi_to_uecontext[imsi].get_sqn()
            result = True
            return unhexlify(user_key), unhexlify(user_amf), unhexlify(user_op), user_sqn, result
        except Exception, e:
            print "\tError %s while extracting data from user with IMSI %s" % (e, imsi)
            result = False
            return "", "", "", "", result

    '''
    def apply_128_eia1(self, imsi, count, bearer, direction, data):
        snow = SNOW3G()
        
        # ik [16 bytes], count [uint32], bearer [uint32], dir [0 or 1], data_in [bytes], length [uint32, length in bits]
        mac = snow.F9(self.imsi_to_uecontext[imsi].get_ik(), count, bearer, direction, data.to_bytes(), (len(data.to_bytes())*8))
        self.imsi_to_uecontext[imsi].set_mac(mac)
 
        return mac
    '''

