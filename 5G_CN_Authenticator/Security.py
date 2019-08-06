import numpy as np
import random
from enum import Enum

'''
Simple Core Network implementation for research purposes
Authors:
    - Gines Garcia-Aviles
    - @github: https://github.com/GinesGarcia
License:
    - MIT License
'''

class SecurityAlgorithm:
    EEA0 = 0
    EIA1_128 = 1
    EIA2_128 = 2

class AlgorithmDistinguisher:
    NAS_ENC = 1
    NAS_INT = 2

class SecurityDirection:
    DOWNLINK = 1
    UPLINK = 0
