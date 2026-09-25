import type { Opportunity } from "./types.js";

export type StructuralFunction = {
  name:string; visibility:"external"|"public"|"internal"|"private"|"unknown"; mutability:"view"|"pure"|"payable"|"nonpayable"|"unknown";
  modifiers:string[]; parameters:string[]; accessControlled:boolean; stateWrites:string[]; externalCalls:string[]; delegateCalls:string[]; valueTransfers:string[]; tokenTransfers:string[];
  signatureOperations:string[]; nonceWrites:string[]; oracleReads:string[]; accountingSignals:string[]; upgradeOperations:string[]; userControlledInputs:string[]; internalCalls:string[];
  hasReentrancyGuard:boolean; stateWriteAfterExternalCall:boolean; initializer:boolean; initializerGuard:boolean; businessCritical:boolean; sensitive:boolean; startLine:number; endLine:number;
};
export type StructuralFileAnalysis={file:string;contracts:string[];stateVariables:string[];functions:StructuralFunction[]};

const SENSITIVE_NAMES=/^(?:withdraw|withdrawAll|sweep|rescue|claim|mint|burn|upgradeTo|upgradeToAndCall|setImplementation|changeAdmin|transferOwnership|renounceOwnership|setOwner|setAdmin|pause|unpause|execute|executeBatch|multicall|delegate|initialize|init|setOracle|setPrice|settle|liquidate|borrow|repay|deposit|redeem)$/i;
const TARGET_NAMES=/\b(?:target|targetContract|recipient|to|destination|implementation|newImplementation|admin|owner|oracle|router|caller|account|user|receiver)\b/i;
const VALUE_NAMES=/\b(?:amount|value|shares|assets|tokenAmount|msg\.value)\b/i;

function stripCommentsAndStrings(source:string){
  return source.replace(/\/\*[\s\S]*?\*\//g,m=>m.replace(/[^\n]/g," ")).replace(/\/\/.*$/gm,"").replace(/"(?:\\.|[^"\\])*"/g,'""').replace(/'(?:\\.|[^'\\])*'/g,"''");
}
function lineAt(source:string,offset:number){return source.slice(0,offset).split(/\r?\n/).length;}
function matchingBrace(source:string,open:number){let depth=0;for(let i=open;i<source.length;i++){if(source[i]==="{")depth++;else if(source[i]==="}"&&--depth===0)return i;}return -1;}
function visibilityOf(signature:string):StructuralFunction["visibility"]{const m=signature.match(/\b(external|public|internal|private)\b/);return(m?.[1] as StructuralFunction["visibility"])??"unknown";}
function mutabilityOf(signature:string):StructuralFunction["mutability"]{const m=signature.match(/\b(view|pure|payable)\b/);return(m?.[1] as StructuralFunction["mutability"])??"nonpayable";}
function modifiersOf(signature:string,parameterText:string){
  const tail=signature.slice(signature.indexOf(")")+1);
  const reserved=new Set(["external","public","internal","private","view","pure","payable","returns","virtual","override"]);
  const names=tail.match(/\b[A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?/g)??[];
  return Array.from(new Set(names.map(x=>x.replace(/\(.*$/,"")).filter(x=>!reserved.has(x)&&x!==parameterText)));
}
function parameterNames(text:string):string[]{
  const names=(text.split(",").map(part=>part.trim().match(/(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)\s*$/)?.[1]).filter((x):x is string=>Boolean(x)));
  return names;
}
function hasAccessControl(signature:string,body:string){
  return /\b(?:only[A-Z][A-Za-z0-9_]*|onlyOwner|onlyAdmin|nonReentrant|whenNotPaused)\b/.test(signature)
    || /\b(?:require|revert|assert)\s*\([^;\n]*(?:msg\.sender|hasRole|owner|admin|authorized)\b/.test(body)
    || /\b(?:hasRole|_checkRole|_authorizeUpgrade)\s*\(/.test(body);
}
function findStateVariables(clean:string):string[]{
  const variables:string[]=[];
  for(const m of clean.matchAll(/\b(?:uint(?:8|16|32|64|128|256)?|int(?:8|16|32|64|128|256)?|address|bool|bytes(?:32)?|mapping\s*\([^;]+\)|string)\s+(?:public|private|internal)?\s*(?:immutable|constant)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:=[^;]*)?;/g)) variables.push(m[1]);
  return Array.from(new Set(variables));
}
function calledFunctions(body:string,self:string):string[]{
  const ignored=new Set(["if","for","while","require","revert","assert","return","emit","abi"]);
  const names:string[]=[];
  for(const m of body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*\(/g)){
    const n:string=m[1];
    if(n!==self&&!ignored.has(n)&&!names.includes(n)) names.push(n);
  }
  return names;
}

export function analyzeSolidityStructure(source:string,file="unknown.sol"):StructuralFileAnalysis{
  const clean=stripCommentsAndStrings(source);
  const contracts:string[]=Array.from(clean.matchAll(/\b(?:contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)/g),m=>m[1]);
  const stateVariables=findStateVariables(clean);
  const functions:StructuralFunction[]=[];
  const functionRe=/\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)([^\{;]*?)\{/g;

  for(const match of clean.matchAll(functionRe)){
    const open=match.index!+match[0].lastIndexOf("{"),close=matchingBrace(clean,open);
    if(close<0)continue;
    const signature=match[0],body=clean.slice(open+1,close),params=parameterNames(match[2]),modifiers=modifiersOf(signature,match[2]);
    const stateWrites:string[]=Array.from(new Set(Array.from(body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)(?:\s*\[[^\]]+\])?\s*(?:\+=|-=|\*=|\/=|%=|=)/g),m=>m[1]))).filter((name:string)=>stateVariables.includes(name));
    const externalCalls:string[]=Array.from(new Set(Array.from(body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\.(?:call|callcode|staticcall)\s*(?:\{|\()/g),m=>m[1])));
    const delegateCalls:string[]=Array.from(new Set(Array.from(body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\.delegatecall\s*\(/g),m=>m[1])));
    const valueCallTargets:string[] = Array.from(body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\.call\s*\{\s*value\s*:/g)).map(m=>m[1]);
    const nativeTransfers:string[] = Array.from(body.matchAll(/\b(?:transfer|send)\s*\(/g)).map(() => "native-transfer");
    const valueTransfers:string[] = Array.from(new Set([...valueCallTargets,...nativeTransfers]));
    const tokenTransfers:string[]=Array.from(new Set(Array.from(body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\.(transfer|transferFrom|safeTransfer|safeTransferFrom|approve|safeApprove)\s*\(/g),m=>`${m[1]}.${m[2]}`)));
    const signatureOperations:string[]=Array.from(new Set(Array.from(body.matchAll(/\b(?:ecrecover|ECDSA\.(?:recover|toEthSignedMessageHash)|SignatureChecker\.|permit\s*\()/g),m=>m[0].replace(/\s+/g,""))));
    const nonceWrites:string[]=Array.from(new Set(Array.from(body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*nonce[A-Za-z0-9_]*)\s*(?:\+\+|--|\+=|=)/gi),m=>m[1])));
    const oracleReads:string[]=Array.from(new Set(Array.from(body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\.(?:latestRoundData|getPrice|getAssetPrice|latestAnswer|consult|quote)\s*\(/g),m=>m[1])));
    const accountingSignals:string[]=Array.from(new Set(Array.from(body.matchAll(/\b(?:balanceOf|totalSupply|totalAssets|totalShares|debt|shares|assets|liquidity|reserve|collateral|balance)\b/gi),m=>m[0].toLowerCase())));
    const upgradeOperations:string[]=Array.from(new Set(Array.from(body.matchAll(/\b(?:upgradeTo|upgradeToAndCall|setImplementation|changeAdmin|_upgradeTo|_setImplementation)\s*\(/g),m=>m[0].replace(/\s+/g,""))));
    const internalCalls=calledFunctions(body,match[1]);
    const userControlledInputs:string[]=params.filter((p:string)=>TARGET_NAMES.test(p)||VALUE_NAMES.test(p));
    const externalPositions:number[]=Array.from(body.matchAll(/\b[A-Za-z_][A-Za-z0-9_]*\.(?:call|callcode|staticcall|delegatecall)\s*(?:\{|\()/g),m=>m.index??0);
    const lastExternal=externalPositions.length?Math.max(...externalPositions):-1;
    const statePositions:number[]=Array.from(body.matchAll(/\b[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\])?\s*(?:\+=|-=|\*=|\/=|%=|=)/g),m=>m.index??0);
    const firstStateWrite=statePositions[0]??-1;
    const hasReentrancyGuard=/\bnonReentrant\b/.test(signature)||/\b(?:ReentrancyGuard|reentrancyGuard)\b/.test(body);
    const initializer=/^(?:initialize|init)$/i.test(match[1]);
    const initializerGuard=/\b(?:initializer|reinitializer)\b/.test(signature)||/\b_initialized\b|\b_initializedVersion\b/.test(body);
    const businessCritical=/^(?:withdraw|withdrawAll|sweep|rescue|claim|mint|burn|execute|executeBatch|settle|liquidate|borrow|repay|deposit|redeem|swap|flashLoan|flashBorrow|vote|propose)$/i.test(match[1]);
    functions.push({name:match[1],visibility:visibilityOf(signature),mutability:mutabilityOf(signature),modifiers,parameters:params,accessControlled:hasAccessControl(signature,body),stateWrites,externalCalls,delegateCalls,valueTransfers,tokenTransfers,signatureOperations,nonceWrites,oracleReads,accountingSignals,upgradeOperations,userControlledInputs,internalCalls,hasReentrancyGuard,stateWriteAfterExternalCall:lastExternal>=0&&firstStateWrite>lastExternal,initializer,initializerGuard,businessCritical,sensitive:SENSITIVE_NAMES.test(match[1]),startLine:lineAt(source,match.index!),endLine:lineAt(source,close)});
  }
  return {file,contracts:Array.from(new Set(contracts)),stateVariables,functions};
}

export function structuralFindings(analysis:StructuralFileAnalysis):Opportunity[]{
  const findings:Opportunity[]=[];
  for(const fn of analysis.functions){
    if(!["external","public"].includes(fn.visibility)||fn.mutability==="view"||fn.mutability==="pure")continue;
    const evidenceBase=[`function ${fn.name} (${fn.visibility}, ${fn.mutability}) lines ${fn.startLine}-${fn.endLine}`,`parameters=${fn.parameters.join(",")||"none"}`,`accessControl=${fn.accessControlled}`,`stateWrites=${fn.stateWrites.join(",")||"none"}`,`externalCalls=${fn.externalCalls.join(",")||"none"}`,`delegateCalls=${fn.delegateCalls.join(",")||"none"}`,`valueTransfers=${fn.valueTransfers.join(",")||"none"}`];
    if(fn.sensitive&&!fn.accessControlled)findings.push({id:`structural:unrestricted-sensitive-function:${analysis.file}:${fn.startLine}`,programId:"unknown",title:`Sensitive externally reachable function without detected access control: ${fn.name}`,category:"access-control",severity:"high",confidence:(fn.stateWrites.length||fn.valueTransfers.length)?.72:.62,evidence:[...evidenceBase,"review candidate: sensitive function name plus no detected authorization guard."],status:"new",createdAt:new Date().toISOString()});
    if(fn.delegateCalls.length&&fn.userControlledInputs.length&&!fn.accessControlled)findings.push({id:`structural:user-controlled-delegatecall:${analysis.file}:${fn.startLine}`,programId:"unknown",title:`User-controlled delegatecall path in externally reachable function: ${fn.name}`,category:"external-call",severity:"critical",confidence:.84,evidence:[...evidenceBase,"review candidate: user-influenced parameter and delegatecall occur in the same externally reachable function without detected access control."],status:"new",createdAt:new Date().toISOString()});
    if(fn.externalCalls.length&&fn.valueTransfers.length&&fn.userControlledInputs.length&&!fn.accessControlled)findings.push({id:`structural:user-controlled-value-call:${analysis.file}:${fn.startLine}`,programId:"unknown",title:`User-controlled value-forwarding external call path: ${fn.name}`,category:"external-call",severity:"high",confidence:.78,evidence:[...evidenceBase,"review candidate: external call forwards value and accepts target/value-like user input without detected access control."],status:"new",createdAt:new Date().toISOString()});
  }
  return findings;
}
