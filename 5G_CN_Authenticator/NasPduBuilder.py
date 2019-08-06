from pycrate_mobile.NAS import *
from pycrate_asn1rt.utils import *
from pycrate_mobile.TS24008_IE import PLMN
from pycrate_mobile.TS24301_EMM import EMMHeaderSec
from pycrate_corenet.utils import *

'''
Simple Core Network implementation for research purposes
Authors:
    - Gines Garcia-Aviles
    - @github: https://github.com/GinesGarcia
License:
    - MIT License
'''

def build_authentication_request_pdu(rand, autn):
    nas_pdu = EMMAuthenticationRequest()
    nas_pdu['RAND'][0].set_val(rand)
    nas_pdu['AUTN'][1].set_val(autn)

    return nas_pdu


def build_security_mode_command_pdu(k_nas_int, direction, ciphering_algorithm, integrity_algorithm, ue_caps):
    #TODO: check input parameters
    # UESecCap returns a 4 bytes header that includes extra values not recognized by OAISIM.
    # That is why here, we take only two bytes.
    ue_sec_caps = NAS.UESecCap(val={'EEA0':ue_caps['EEA0'], 'EEA1_128':ue_caps['128-EEA1'], 
        'EEA2_128':ue_caps['128-EEA2'],'EEA3_128':ue_caps['128-EEA3'],'EEA4':ue_caps['EEA4'], 
        'EEA5':ue_caps['EEA5'], 'EEA6':ue_caps['EEA6'], 'EEA7':ue_caps['EEA7'],
        'EIA0':ue_caps['EIA0'], 'EIA1_128':ue_caps['128-EIA1'], 'EIA2_128':ue_caps['128-EIA2'], 
        'EIA3_128':ue_caps['128-EIA3'],'EIA4':ue_caps['EIA4'], 'EIA5':ue_caps['EIA5'], 
        'EIA6':ue_caps['EIA6'], 'EIA7':ue_caps['EIA7']}).to_bytes()[:2]

    nas_pdu = EMMSecurityModeCommand(val={'SecHdr':0, 'NASSecAlgo':{'CiphAlgo':ciphering_algorithm, 'IntegAlgo':integrity_algorithm}, 'UESecCap':ue_sec_caps, 'IMEISVReq':1})

    # Adds integrity to the PDU by generating and adding a 4 bytes mac plus a security header
    sec_nas_pdu = EMMSecProtNASMessage(val={'EMMHeaderSec': {'SecHdr': 3, 'ProtDisc': 7},'Seqn': 0,'NASMessage': nas_pdu.to_bytes()})
    sec_nas_pdu.mac_compute(k_nas_int, direction, integrity_algorithm, 0)
    return sec_nas_pdu

def build_attach_accept_pdu(plmn, direction, k_nas_int, integrity_algorithm, k_nas_enc, ciphering_algorithm, assigned_ip):
    # TODO: Replace al hardcoded values with parameters received from handler

    # TODO: Manage multiple TAI
    # Tracking Area Identity List
    tai_list = PartialTAIList1(val={'Type':1,'PLMN': PLMN(val=plmn).to_bytes(), 'TAC0':1})
    
    
    # ESM Message container
    esm = ESMActDefaultEPSBearerCtxtRequest(val={'EPSBearerId': 5, 'PTI': 1, 'APN': [{'Value': 'acho.ipv4'}], 'APN_AMBR':{'DL':254, 'UL':254,'DLExt':222, 'ULExt':158}, 'ProtConfig':{'Ext':1}, 'PDNAddr':{'Addr':inet_aton_cn(1, assigned_ip)}})
    #esm['PDNAddr']['V'].set_val(inet_aton_cn(1, assigned_ip))
   
    # EPS Mobile identity - GUTI. 
    '''
    encode(type, ident) sets the mobile identity with given type
        type: IDTYPE_GUTI = 6
        ident: 4-tuple (PLMN -string of digits-, MMEGroupID -uint16-, MMECode -uint8-, MTMSI -uint32-)
    '''
    eps_mob_id_guti = EPSID()
    eps_mob_id_guti.encode(6, [PLMN(val=plmn).to_bytes(), 4, 1, 541709315])

    # GPRS Timer
    t_3402 = GPRSTimer(val={'Unit':1, 'Value':12})

    # EMMAttachAccept
    nas_pdu = EMMAttachAccept(val={'SecHdr': 0, 'EPSAttachResult':{'Value':1},'T3412':{'Unit':2, 'Value':9},'TAIList': tai_list.to_bytes(),'ESMContainer': esm.to_bytes(),'GUTI': eps_mob_id_guti.to_bytes(),'T3402': t_3402.to_bytes()})

    nas_pdu['EPSAttachResult'][0].set_val(1)
    #print show(nas_pdu['EPSAttachResult'])

    # Integrity protected and ciphered
    sec_nas_pdu = EMMSecProtNASMessage(val={'SecHdr': 2,'Seqn': 0,'NASMessage': nas_pdu.to_bytes()})
    sec_nas_pdu.encrypt(k_nas_enc, direction, ciphering_algorithm, 0)
    sec_nas_pdu.mac_compute(k_nas_int, direction, integrity_algorithm, 1)

    return sec_nas_pdu
