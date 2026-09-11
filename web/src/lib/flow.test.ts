import{describe,it,expect}from'vitest';import{endpointName,tuple}from'./flow';
describe('flow helpers',()=>{it('formats endpoint',()=>expect(endpointName({namespace:'ns',podName:'p'})).toBe('ns/p'));it('formats tuple',()=>expect(tuple({IP:{source:'1.1.1.1',destination:'2.2.2.2'},l4:{TCP:{sourcePort:10,destinationPort:443}}})).toContain('443'))});
