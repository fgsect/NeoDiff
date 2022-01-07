"""
AFL support for python neo VM
Run with:
```bash
AFL_AUTORESUME=1 PATH="./AFLplusplus:${PATH}" py-afl-fuzz -i in -t 2000 -o out -U -m none -M main -- $(which python3) ./neo-python-VM.afl.py
```
"""

import os
import binascii
from io import BytesIO, BufferedReader
import sys
import hashlib
from logzero import logger
from itertools import chain
import json
import struct
import pathlib
import glob
import trace

import os
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../neo-python/')

from neo.VM.ExecutionEngine import ExecutionEngine
from neo.SmartContract.ApplicationEngine import ApplicationEngine
from neo.SmartContract import TriggerType
from neo.VM import OpCode
from neo.VM import VMState
from neo.VM import InteropService
from neo.Core.Cryptography.Crypto import Crypto
from neo.Core.Fixed8 import Fixed8
from neo.Core.IO.BinaryReader import BinaryReader


#stream = open('code','rb')

TYPE2BYTE = {
    InteropService.Integer: '1',
    InteropService.ByteArray: '2',
    InteropService.Array: '3',
    InteropService.Boolean: '4',
    InteropService.Map: '5',
    InteropService.Struct: '6',
    InteropService.InteropInterface: '7',
}

class Checksum:
    def __init__(self):
        self.reset()
    def reset(self):
        self.data = b''
    def update(self, b):
        #self.sum.update(b)
        #logger.error(binascii.hexlify(b).decode('ascii'))
        self.data += b
        #print(self.result())
    def result(self):
        sha = hashlib.sha1()
        #print(binascii.hexlify(self.data).decode('ascii'))
        sha.update(self.data)
        return sha.hexdigest()

def getItemAsBytes(item):
    #logger.info(item)
    #logger.info(type(item))
    if type(item) == InteropService.Struct or type(item) == InteropService.Array:
        out = b''
        for value in item.GetArray():
            out += getItemAsBytes(value)
        return out
    elif type(item) == InteropService.Map:
        out = b''
        for key in item.Keys:
            out += getItemAsBytes(key)
            out += getItemAsBytes(item.GetItem(key))
        #logger.info('parse map: '+out)
        return out
    elif type(item) == InteropService.InteropInterface:
        return b'InteropInterface'
    else:
        return item.GetByteArray()

#code = bytes.fromhex('552a3694b5ee4e14e7e63ec0b79f3d8f4ecb64fb9f12e9d06351e33f5df3457d428c9221301c099a0638f0b5054f3a5ec21483863cd91cf2e746f755df55e831ed1b7bc54ed741c24d69aae564caf5344e1e855ea7dca16b37e36dd8fb2458e0a4e3e3f1a8bc674e3603481c3fbb142786f9b809c42d45b16c653d77096b1376f9e557f3a77e368a297e68aa4e665ef6d301323c6342e8eaca7a8889672fb6ad8f4353c43149820711a1d652576fceaeac6902de44d5e2a88e347ff11bd6b3e4dfc0eccddd375b75d62b078d17d2ed8016ea7658308261e604e28dafc28999f6c4cbe85c0c2ff52616f5ad2a089f28c12519887ed8f1b49b8c7c03988b775d')
#code = bytes.fromhex('55556818')+b'System.Header.GetVersion'+bytes.fromhex('55'*1024)
#code = bytes.fromhex('55555555c5c2')

#code = bytes.fromhex(sys.argv[1])
#print(binascii.hexlify(code))

OPCODES = {}
OPCODES_COVERAGE_NEWT = {}
OPCODES_COVERAGE_OLDT = {}
OPCODES_TYPEHASHES = {}

def log(m):
    with open('coverage.log', 'a+') as f:
        logger.info(m)
        f.write("{}\n".format(m))
    

def log_coverage(state):
    #logger.info(state)
    if not os.path.isfile('/tmp/trace_now'):
        return
    typehash = "{}_{}".format(state['opcode'], state['data'])
    op = state['opcode']

    if op not in OPCODES_COVERAGE_NEWT:
        OPCODES_COVERAGE_NEWT[op] = 0

    if op not in OPCODES_COVERAGE_OLDT:
        OPCODES_COVERAGE_OLDT[op] = 0

    if op not in OPCODES_TYPEHASHES:
        OPCODES_TYPEHASHES[op] = set()

    
    #logger.info('new unique typehash: {} gather coverage info'.format(typehash))
    coverage = {}
    for fname in glob.glob('/tmp/neo-python.*'):
        #logger.info(fname)
        with open(fname) as f:
            lines = f.read().splitlines()
            if fname not in coverage:
                coverage[fname] = ''
            for i in range(0, len(lines)):
                line = lines[i]
                if not line.startswith('>>>>>>'):
                    if line.strip() and line[5] == ':':
                        #logger.info("{}: {}".format(i, repr(line)))
                        coverage[fname] += '1'
                        continue
                coverage[fname] += '0'

    if op not in OPCODES:
        OPCODES[op] = coverage

        #log("[{}] typehash for opcode {} is new. first coverage info".format(typehash, op))
    else:
        NEW_NEW_COVERAGE = False
        for fname in coverage:
            NEW_COVERAGE = False
            if fname in OPCODES[op]:
                new_coverage = ''
                for a,b in zip(OPCODES[op][fname], coverage[fname]):
                    if a == '1' or b=='1':
                        new_coverage+='1'
                    else:
                        new_coverage+='0'

                    if a=='0' and b=='1':
                        NEW_COVERAGE = True
                        NEW_NEW_COVERAGE = True
            if NEW_COVERAGE:
                #log("[{}] typehash lead to new coverage in opcode {}".format(typehash, op))
                #log("old coverage: {}:{}".format(fname, OPCODES[op][fname]))
                #log("new coverage: {}:{}".format(fname, coverage[fname]))
                #log("sum coverage: {}:{}".format(fname, new_coverage))
                OPCODES[op][fname] = new_coverage
        if NEW_NEW_COVERAGE:
            log("OP: {} Typehashes:{} CoverageOldTypehash:{} CoverageNewTypehash:{}".format(op, len(OPCODES_TYPEHASHES[op]), OPCODES_COVERAGE_OLDT[op], OPCODES_COVERAGE_NEWT[op]))
        
        if NEW_NEW_COVERAGE and typehash not in OPCODES_TYPEHASHES[op]:
            OPCODES_COVERAGE_NEWT[op] += 1
        if NEW_NEW_COVERAGE and typehash in OPCODES_TYPEHASHES[op]:
            OPCODES_COVERAGE_OLDT[op] += 1
    
    OPCODES_TYPEHASHES[op].add(typehash)
    OPCODES[op] = coverage
    with open('coverage.summary', 'w') as f:
        f.write("Opcode\tTypehashes\tCoverageOldTypes\tCoverageNewTypes\n")
        for op in OPCODES:
            f.write("{}\t{}\t{}\t{}\n".format(op, len(OPCODES_TYPEHASHES[op]), OPCODES_COVERAGE_OLDT[op], OPCODES_COVERAGE_NEWT[op]))
    #logger.info(OPCODES[op])
    #exit(0)
        

def run(code, depth=50):
    #logger.info(trace)
    out_data = []
    checksum = Checksum()
    #stream = BytesIO(b"\x02AB")
    stream = BufferedReader(BytesIO(code))
    accounts = None
    validators = None
    assets = None
    contracts = None
    storages = None
    wb = None
    # service = neo.StateMachine(accounts, validators, assets, contracts, storages, wb)

    #engine = neo.ExecutionEngine(crypto=neo.Crypto)
    class FakeCrypto:
        def Hash160(*_):
            #raise Exception("Not Implemented Crypto")
            pass

        def Hash256(*_):
            raise Exception("Not Implemented Crypto")

        def VerifySignature(message, signature, public_key, unhex=True):
            raise Exception("Not Implemented Crypto")
    engine = ExecutionEngine(crypto=FakeCrypto)
    tx = {}
    """
    engine = ApplicationEngine(
        trigger_type=TriggerType.Application,
        container=tx,
        gas=Fixed8.Zero(),
        testMode=False,
        snapshot={}
    )
    """

    #engine.LoadScript(tx.Script)

    #success = engine.Execute()
    context = engine.LoadScript(script=code)

    context.OpReader = BinaryReader(stream)
    context.__OpReader = BinaryReader(stream)

    engine._VMState &= ~VMState.BREAK
    has_returned = False;
    i = 0
    while not has_returned and engine._VMState & VMState.HALT == 0 and engine._VMState & VMState.FAULT == 0:
        #try:
        
        peek = stream.peek(1)[0:1]
        if len(peek) == 0:
            break
        checksum.update(struct.pack("I", engine.CurrentContext.InstructionPointer))
        opcode = None
        COVERAGE = False
        try:
            loop_data = {'opcode': None, 'ret': None, 'data': '', 'vmstate': 0, 'crash': False, 'checksum': ''}
            opcode = engine.CurrentContext.CurrentInstruction.OpCode
            loop_data['opcode'] = opcode[0]
            checksum.update(struct.pack("I", struct.unpack("B", opcode)[0]))
            
            if opcode!=b'\x66':
                if os.path.isfile('/tmp/trace_now'):
                    t = trace.Trace(trace=False)
                    t.runfunc(engine.ExecuteNext)
                    r = t.results()
                    r.write_results(coverdir="/tmp", show_missing=True)
                    COVERAGE = True
                else:
                    engine.ExecuteNext()
                #logger.info(r)
            else:
                #logger.info(engine._VMState)
                #logger.info(trace)
                
                for item in engine.CurrentContext._EvaluationStack.Items[-2:]:
                    if type(item) == InteropService.Array:
                        arr = item.GetArray()
                        #logger.error(arr)
                        if len(arr) == 2:
                            ret_id, val = item.GetArray()
                            if type(ret_id) == neo.ByteArray:
                                b = getItemAsBytes(val)
                                out = b'ret,'+struct.pack("II", ret_id.GetBigInteger(), len(b))+b
                                loop_data['ret'] = (ret_id.GetBigInteger(), b)
                #out_data.append(loop_data)
                has_returned = True;
            
            loop_data['vmstate'] = engine._VMState & 0x3
            stack_types = ''
            
            for item in engine.CurrentContext._EvaluationStack.Items[::-1]:
                #if trace:
                #    logger.info(binascii.hexlify(getItemAsBytes(item)).decode('ascii'))
                if len(stack_types) < 2:
                    stack_types += TYPE2BYTE[type(item)]
                checksum.update(getItemAsBytes(item))
            
            for item in engine.CurrentContext._AltStack.Items[::-1]:
                #if trace:
                #    logger.info(binascii.hexlify(getItemAsBytes(item)).decode('ascii'))
                if len(stack_types) < 2:
                    stack_types += TYPE2BYTE[type(item)]
                checksum.update(getItemAsBytes(item))
            
            loop_data['data'] = stack_types
            loop_data['checksum'] = checksum.result()
            
            
            
            if engine._VMState & VMState.FAULT != 0:
                #logger.error("FAULT")
                loop_data['crash'] = True
                if COVERAGE:
                    log_coverage(loop_data)
                out_data.append(loop_data)
                break
            
            if COVERAGE:
                log_coverage(loop_data)
            out_data.append(loop_data)
        except Exception as e:
            #logger.exception(e)
            loop_data['crash'] = True
            loop_data['checksum'] = checksum.result()
            if COVERAGE:
                log_coverage(loop_data)
            out_data.append(loop_data)
            break
        
        i += 1

        #logger.info(i)
        if i>depth:
            #logger.info('exec timeout (code length: {})'.format(len(code)))
            #logger.info(out_data)
            break
    
    return out_data
    #print("DONE")

#code = bytes.fromhex('552a3694b5ee4e14e7e63ec0b79f3d8f4ecb64fb9f12e9d06351e33f5df3457d428c9221301c099a0638f0b5054f3a5ec21483863cd91cf2e746f755df55e831ed1b7bc54ed741c24d69aae564caf5344e1e855ea7dca16b37e36dd8fb2458e0a4e3e3f1a8bc674e3603481c3fbb142786f9b809c42d45b16c653d77096b1376f9e557f3a77e368a297e68aa4e665ef6d301323c6342e8eaca7a8889672fb6ad8f4353c43149820711a1d652576fceaeac6902de44d5e2a88e347ff11bd6b3e4dfc0eccddd375b75d62b078d17d2ed8016ea7658308261e604e28dafc28999f6c4cbe85c0c2ff52616f5ad2a089f28c12519887ed8f1b49b8c7c03988b775d')
#code = bytes.fromhex('55556829')+b'System.ExecutionEngine.GetScriptContainer'+bytes.fromhex('55'*1)
#code = binascii.unhexlify('55545352c5c2')
#out_data = run(code, False)

#print(out_data)

import os
import afl
import sys

if __name__ == "__main__":

    print("Moin")
    
    depth = 50
    while afl.loop(1000):
        print("Still moin")
        sys.stdin.seek(0)
        run(sys.stdin.buffer.read(), depth)
    os._exit(1)
    if len(sys.argv)>1:
        depth = int(sys.argv[1])
        #logger.info("depth: {}".format(depth))
    
        if len(sys.argv) > 3:
            if sys.argv[2] == 'code':
                out_data = run(binascii.unhexlify(sys.argv[3]), depth)
                out_json = json.dumps(out_data)
                print(out_json)
                exit(0)

    #while True:
    #logger.info("read len")
    raw_length = sys.stdin.buffer.read(2)
    length = struct.unpack("=H", raw_length)[0]
    #logger.info(trace)
    if length == 0:
        sys.exit(0)
    #logger.info("read code")
    code = sys.stdin.buffer.read(length)
    
    
    out_data = run(code, depth)
    out_json = json.dumps(out_data).encode('ascii')
    #logger.info("write size {}".format(len(out_json)))
    sys.stdout.buffer.write(struct.pack("I", len(out_json)))
    #logger.info("write json")
    sys.stdout.buffer.write(out_json)
    #logger.info("write flush")
    sys.stdout.buffer.flush()
