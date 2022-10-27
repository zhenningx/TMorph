# -*- coding: utf-8 -*-
"""
Created on Sun Feb  2 12:15:11 2020

@author: dxu
"""


class Transform_Operation(object):
    """
    Apply different transform operations.
    """
    def __init__(self, inputSession, packets): #should only take pp
        self.packets = packets       
        self.inputSession = inputSession
        
        
    def validate(self):
        assert len(self.inputSession)==5, 'Input session is not a five-tuple'

        
    def operate(self):
        pass
        
        
