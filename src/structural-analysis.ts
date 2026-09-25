import type { Opportunity, Severity } from "./types.js";

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
function strip(s:string){return s.replace(/\/\*[\s\S]*?\*\//g,m=>m.replace(/[^\n]/g," ")).replace(/\/\/.*$/gm,"").replace(/"(?:\\.|[^"\\])*"/g,'""').replace(/'(?:\\.|[^'\\])*'/g,"''");}
function lineAt(s:string,o:number){return s.slice(0,o).split(/\r?\n/).length;}
function brace(s:string,o:number){let d=0;for(let i=o;i<s.length;i++){if(s[i]==="{")d++;else if(s[i]==="}"&&--d===0)return i;}return -1;}
function visibility(s:string):StructuralFunction["visibility"]{const m=s.match(/\b(external|public|internal|private)\b/);return(m?.[1] as any)??"unknown";}
function mutability(s:string):StructuralFunction["mutability"]{const m=s.match(/\b(view|pure|payable)\b/);return(m?.[1] as any)??"nonpayable";}
function modifiers(s:string,p:string){const reserved=new Set(["external","public","internal","private","view","pure","payable","returns","virtual","override"]);return[...new Set((s.slice(s.indexOf(")")+1).match(/\b[A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?/g)??[]).map(x=>x.replace(/\(.*$/,"")).filter(x=>!reserved.has(x)&&x!==p))];}
function params(s:string){return s.split(",").map(x=>x.trim().match(/(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)\s*$/)?.[1]).filter((x):x is string=>Boolean(x));}
function access(s:string,b:string){return /\b(?:only[A-Z][A-Za-z0-9_]*|onlyOwner|onlyAdmin|nonReentrant|whenNotPaused)\b/.test(s)||/\b(?:require|revert|assert)\s*\([^;\n]*(?:msg\.sender|hasRole|owner|admin|authorized)\b/.test(b)||/\b(?:hasRole|_checkRole|_authorizeUpgrade)\s*\(/.test(b);}
function states(c:string){const v:string[]=[];for(const m of c.matchAll(/\b(?:uint(?:8|16|32|64|128|256)?|int(?:8|16|32|64|128|256)?|address|bool|bytes(?:32)?|mapping\s*\([^;]+\)|string)\s+(?:public|private|internal)?\s*(?:immutable|constant)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:=[^;]*)?;/g))v.push(m[1]);return[...new Set(v)];}
export function analyzeSolidityStructure(source:string,file="unknown.sol"):StructuralFileAnalysis{
  const clean=strip(source),contracts=[...clean.matchAll(/\b(?:contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)/g)].map(m=>m[1]),stateVariables=states(clean),functions:StructuralFunction[]=[];
  const re=/\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)([^\{;]*?)\{/g;
  for(const match of clean.matchAll(re)){const open=match.index!+match[0].lastIndexOf("{"),close=brace(clean,open);if(close<0)continue;const sig=match[0],body=clean.slice(open+1,close),ps=params(match[2]),mods=modifiers(sig,match[2]);
    const stateWrites=[...new Set([...body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)(?:\s*\[[^\]]+\])?\s*(?:\+=|-=|\*=|\/=|%=|=)/g)].map(m=>m[1]).filter(n=>stateVariables.includes(n)))];
    const externalCalls=[...new Set([...body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\.(?:call|callcode|staticcall)\s*(?:\{|\()/g)].map(m=>m[1]))];
    const delegateCalls=[...new Set([...body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\.delegatecall\s*\(/g)].map(m=>m[1]))];
    const valueTransfers=[...new Set([...body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\.call\s*\{\s*value\s*:/g)].map(m=>m[1]),...[...body.matchAll(/\b(?:transfer|send)\s*\(/g)].map(()=>"native-transfer"))];
    const tokenTransfers=[...new Set([...body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\.(transfer|transferFrom|safeTransfer|safeTransferFrom|approve|safeApprove)\s*\(/g)].map(m=>`${m[1]}.${m[2]}`))];
    const signatureOperations=[...new Set([...body.matchAll(/\b(?:ecrecover|ECDSA\.(?:recover|toEthSignedMessageHash)|SignatureChecker\.|permit\s*\()/g)].map(m=>m[0].replace(/\s+/g,"")))];
    const nonceWrites=[...new Set([...body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*nonce[A-Za-z0-9_]*)\s*(?:\+\+|--|\+=|=)/gi)].map(m=>m[1]))];
    const oracleReads=[...new Set([...body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\.(?:latestRoundData|getPrice|getAssetPrice|latestAnswer|consult|quote)\s*\(/g)].map(m=>m[1]))];
    const accountingSignals=[...new Set([...body.matchAll(/\b(?:balanceOf|totalSupply|totalAssets|totalShares|debt|shares|assets|liquidity|reserve|collateral|balance)\b/gi)].map(m=>m[0].toLowerCase()))];
    const upgradeOperations=[...new Set([...body.matchAll(/\b(?:upgradeTo|upgradeToAndCall|setImplementation|changeAdmin|_upgradeTo|_setImplementation)\s*\(/g)].map(m=>m[0].replace(/\s+/g,"")))];
    const internalCalls=[...new Set([...body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*\(/g)].map(m=>m[1]).filter(n=>n!==match[1]&&!["if","for","while","require","revert","assert","return","emit","abi"].includes(n)))];
    const userControlledInputs=ps.filter(p=>TARGET_NAMES.test(p)||VALUE_NAMES.test(p));
    const extPos=[...body.matchAll(/\b[A-Za-z_][A-Za-z0-9_]*\.(?:call|callcode|staticcall|delegatecall)\s*(?:\{|\()/g)].map(m=>m.index??0),lastExternal=extPos.length?Math.max(...extPos):-1;
    const firstStateWrite=[...body.matchAll(/\b[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\])?\s*(?:\+=|-=|\*=|\/=|%=|=)/g)].map(m=>m.index??0)[0]??-1;
    const hasReentrancyGuard=/\bnonReentrant\b/.test(sig)||/\b(?:ReentrancyGuard|reentrancyGuard)\b/.test(body),initializer=/^(?:initialize|init)$/i.test(match[1]),initializerGuard=/\b(?:initializer|reinitializer)\b/.test(sig)||/\b_initialized\b|\b_initializedVersion\b/.test(body),businessCritical=/^(?:withdraw|withdrawAll|sweep|rescue|claim|mint|burn|execute|executeBatch|settle|liquidate|borrow|repay|deposit|redeem|swap|flashLoan|flashBorrow|vote|propose)$/i.test(match[1]);
    functions.push({name:match[1],visibility:visibility(sig),mutability:mutability(sig),modifiers:mods,parameters:ps,accessControlled:access(sig,body),stateWrites,externalCalls,delegateCalls,valueTransfers,tokenTransfers,signatureOperations,nonceWrites,oracleReads,accountingSignals,upgradeOperations,userControlledInputs,internalCalls,hasReentrancyGuard,stateWriteAfterExternalCall:lastExternal>=0&&firstStateWrite>lastExternal,initializer,initializerGuard,businessCritical,sensitive:SENSITIVE_NAMES.test(match[1]),startLine:lineAt(source,match.index!),endLine:lineAt(source,close)});
  } return {file,contracts:[...new Set(contracts)],stateVariables,functions};
}
export function structuralFindings(analysis:StructuralFileAnalysis):Opportunity[]{
 const findings:Opportunity[]=[];for(const fn of analysis.functions){if(!["external","public"].includes(fn.visibility)||fn.mutability==="view"||fn.mutability==="pure")continue;
 const evidenceBase=[`function ${fn.name} (${fn.visibility}, ${fn.mutability}) lines ${fn.startLine}-${fn.endLine}`,`parameters=${fn.parameters.join(",")||"none"}`,`accessControl=${fn.accessControlled}`,`stateWrites=${fn.stateWrites.join(",")||"none"}`,`externalCalls=${fn.externalCalls.join(",")||"none"}`,`delegateCalls=${fn.delegateCalls.join(",")||"none"}`,`valueTransfers=${fn.valueTransfers.join(",")||"none"}`];
 if(fn.sensitive&&!fn.accessControlled)findings.push({id:`structural:unrestricted-sensitive-function:${analysis.file}:${fn.startLine}`,programId:"unknown",title:`Sensitive externally reachable function without detected access control: ${fn.name}`,category:"access-control",severity:"high",confidence:fn.stateWrites.length||fn.valueTransfers.length?.72:.62,evidence:[...evidenceBase,"review candidate: sensitive function name plus no detected authorization guard."],status:"new",createdAt:new Date().toISOString()});
 if(fn.delegateCalls.length&&fn.userControlledInputs.length&&!fn.accessControlled)findings.push({id:`structural:user-controlled-delegatecall:${analysis.file}:${fn.startLine}`,programId:"unknown",title:`User-controlled delegatecall path in externally reachable function: ${fn.name}`,category:"external-call",severity:"critical",confidence:.84,evidence:[...evidenceBase,"review candidate: user-influenced parameter and delegatecall occur in the same externally reachable function without detected access control."],status:"new",createdAt:new Date().toISOString()});
 if(fn.externalCalls.length&&fn.valueTransfers.length&&fn.userControlledInputs.length&&!fn.accessControlled)findings.push({id:`structural:user-controlled-value-call:${analysis.file}:${fn.startLine}`,programId:"unknown",title:`User-controlled value-forwarding external call path: ${fn.name}`,category:"external-call",severity:"high",confidence:.78,evidence:[...evidenceBase,"review candidate: external call forwards value and accepts target/value-like user input without detected access control."],status:"new",createdAt:new Date().toISOString()});
 } return findings;
}
