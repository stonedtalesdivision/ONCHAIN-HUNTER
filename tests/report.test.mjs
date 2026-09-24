import test from "node:test";
import assert from "node:assert/strict";
import { buildSecurityReport } from "../dist/report.js";
test("report distinguishes locally reproduced findings", () => {
 const finding={id:"x",programId:"p",title:"candidate",category:"access-control",severity:"high",confidence:0.9,evidence:["A.sol:1"],status:"new",createdAt:new Date().toISOString()};
 const report=buildSecurityReport(finding,{status:"passed",exitCode:0,command:"forge test -vvv",stdout:"",stderr:""});
 assert.equal(report.assessment.conclusion,"locally-reproduced");
 assert.ok(report.submissionChecklist.length >= 5);
});
