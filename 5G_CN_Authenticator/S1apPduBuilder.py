from pycrate_asn1dir import S1AP
from pycrate_asn1rt.utils import *
from pycrate_mobile.TS24008_IE import PLMN
from socket import inet_aton

'''
Simple Core Network implementation for research purposes
Authors:
    - Gines Garcia-Aviles
    - @github: https://github.com/GinesGarcia
License:
    - MIT License
'''

def build_s1setup_response(mme_plmn, mme_gid, mme_code, mme_capacity):
    PDU = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
    # Mode GUMMEI dict can be added 
    ServedGUMMEIs = [
    {
        'servedPLMNs'   : [PLMN(val=mme_plmn).to_bytes(), ], # add more PLMN in this 1st GUMMEI if needed
        'servedGroupIDs': [uint_to_bytes(mme_gid, 16), ],    # add more MME Group ID in this 1st GUMMEI if needed
        'servedMMECs'   : [uint_to_bytes(mme_code, 8), ],    # add more MME Code in this 1st GUMMEI if needed
    },]
    S1SetupIEs = [
        {'id': 105, 'criticality': 'reject', 'value': ('ServedGUMMEIs', ServedGUMMEIs)},
        {'id': 87,  'criticality': 'reject', 'value': ('RelativeMMECapacity', mme_capacity)}, # add more optional IEs if needed
    ]
    S1SetupVal = ('successfulOutcome', {
        'procedureCode': 17,
        'criticality': 'ignore',
        'value': ('S1SetupResponse', {'protocolIEs': S1SetupIEs})
    })
    PDU.set_val(S1SetupVal)
    return PDU.to_aper()

def build_downlink_nas_transport(mme_ue_s1ap_id, enb_ue_s1ap_id, nas_pdu_to_reply):
    PDU = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
    IEs = [
        {'id': 0, 'criticality': 'reject', 'value': ('MME-UE-S1AP-ID', mme_ue_s1ap_id)},
        {'id': 8, 'criticality': 'reject', 'value': ('ENB-UE-S1AP-ID', enb_ue_s1ap_id)},
        {'id': 26, 'criticality': 'reject', 'value': ('NAS-PDU', nas_pdu_to_reply.to_bytes())},
    ]
    S1SetupVal = ('initiatingMessage', {
        'procedureCode': 11,
        'criticality': 'reject',
        'value': ('DownlinkNASTransport', {'protocolIEs': IEs})
    })
    PDU.set_val(S1SetupVal)
    return PDU.to_aper()

def build_downlink_nas_transport_for_attach_accept(mme_ue_s1ap_id, enb_ue_s1ap_id, k_enb, erab_id, gw_teid, nas_pdu_to_reply, gw_ip):

    PDU = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
    erab_list = [{
            'id': 52, 
            'criticality': 'reject', 
            'value':('E-RABToBeSetupItemCtxtSUReq',{
                    'e-RAB-ID': erab_id,
                    'e-RABlevelQoSParameters':{
                        'qCI':9,                                              
                        'allocationRetentionPriority':{                   
                            'priorityLevel':15,
                            'pre-emptionCapability':'may-trigger-pre-emption',  # or 'shall-not-trigger-pre-emption'
                            'pre-emptionVulnerability': 'not-pre-emptable',     # or 'pre-emptable'
                        }             
                    },
                    'transportLayerAddress': (bytes_to_uint(inet_aton(gw_ip), 32), 32),
                    'gTP-TEID': uint_to_bytes(gw_teid, 32),
                    'nAS-PDU': nas_pdu_to_reply.to_bytes(),                
            })
    },]

    IEs = [
        {
            # MME-UE-S1AP-ID
            'id': 0, 
            'criticality': 'reject', 
            'value': ('MME-UE-S1AP-ID', mme_ue_s1ap_id)
        },
        {
            # ENB-UE-S1AP-ID
            'id': 8, 
            'criticality': 'reject', 
            'value': ('ENB-UE-S1AP-ID', enb_ue_s1ap_id)
        },
        {
            # UEAggregateMaximumBitrate
            'id': 66, 
            'criticality': 'reject', 
            'value':('UEAggregateMaximumBitrate',{
                'uEaggregateMaximumBitRateDL': 100000000,
                'uEaggregateMaximumBitRateUL': 500000000      
            })
        },
        {
            # E_RABToBeSetupListCtxtSUReq
            'id': 24, 
            'criticality': 'reject', 
            'value': ('E-RABToBeSetupListCtxtSUReq', erab_list),
        },
        {
            # UESecurityCapabilities
            'id': 107, 
            'criticality': 'reject', 
            'value': ('UESecurityCapabilities', {
                        # 16 bits to enconde UeSecCapabilities
                        'encryptionAlgorithms': (0,16),
                        'integrityProtectionAlgorithms': (16384,16),    
                    })              
        },
        {
            # eNB SecurityKey
            'id': 73, 
            'criticality': 'reject', 
            'value': ('SecurityKey', (bytes_to_uint(k_enb, 256), 256))
        },
    ]
    S1SetupVal = ('initiatingMessage', {
        'procedureCode': 9,
        'criticality': 'reject',
        'value': ('InitialContextSetupRequest', {'protocolIEs': IEs})
    })
    PDU.set_val(S1SetupVal)
    return PDU.to_aper()
