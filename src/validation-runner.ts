import {spawn,execFileSync} from "node:child_process";
import {mkdir,writeFile} from "node:fs/promises";
export type ValidationExecution={status:"passed"|"failed"|"blocked";exitCode:number|null;command:string;stdout:string;stderr:string;artifactPath?:string;startedAt?:string;finishedAt?:string;toolVersions?:Record<string,string>;safety:{localOnly:true;liveNetworkTraffic:false;explicitExecutionRequired:true}};
function versions():Record<string,string>{const r:Record<string,string>={};for(const t of ["forge","anvil"]){try{r[t]=execFileSync(t,["--version"],{encoding:"utf8"}).trim()}catch{r[t]="unavailable"}}return r}
async function persist(x:Omit<ValidationExecution,"artifactPath">,cwd:string){const dir=cwd+"/artifacts/onchain-hunter/validation";await mkdir(dir,{recursive:true});const p=dir+"/forge-test-"+Date.now()+".json";await writeFile(p,JSON.stringify(x,null,2),"utf8");return p}
export async function runLocalFoundryTest(testName?:string,cwd="."):Promise<ValidationExecution>{
 const safety={localOnly:true as const,liveNetworkTraffic:false as const,explicitExecutionRequired:true as const};
 const command=testName?"forge test -vvv --match-test "+testName:"forge test -vvv";
 if(process.env.ONCHAIN_HUNTER_ALLOW_EXECUTION!=="1") return {status:"blocked",exitCode:null,command,stdout:"",stderr:"Execution disabled. Set ONCHAIN_HUNTER_ALLOW_EXECUTION=1 inside an isolated local validation environment.",safety};
 const args=["test","-vvv"];if(testName)args.push("--match-test",testName);const startedAt=new Date().toISOString(),toolVersions=versions();
 return new Promise(resolve=>{const child=spawn("forge",args,{cwd,env:{...process.env},shell:false});let stdout="",stderr="";child.stdout.on("data",d=>stdout+=d.toString());child.stderr.on("data",d=>stderr+=d.toString());
 child.on("error",async err=>{const x={status:"failed" as const,exitCode:null,command,stdout,stderr:stderr+err.message,startedAt,finishedAt:new Date().toISOString(),toolVersions,safety};resolve({...x,artifactPath:await persist(x,cwd)})});
 child.on("close",async code=>{const x={status:code===0?"passed" as const:"failed" as const,exitCode:code,command,stdout,stderr,startedAt,finishedAt:new Date().toISOString(),toolVersions,safety};resolve({...x,artifactPath:await persist(x,cwd)})})})
}
