package com.TheSecureSyndicate.threat_detection_backend;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class ThreatDetectionBackendApplicationTests {

	@Test
	void contextLoads() {
	}

	@org.springframework.beans.factory.annotation.Autowired
	private com.TheSecureSyndicate.threat_detection_backend.service.YaraScanService yaraScanService;

	@Test
	void testPEFunctionParserAndStaticAnalysis() throws Exception {
		java.io.File file = new java.io.File("uploads/3f32530e-9df2-4630-b638-cb4bc5b7944f_Hello.exe");
		if (file.exists()) {
			java.util.List<String> imports = com.TheSecureSyndicate.threat_detection_backend.util.PEFunctionParser.extractImportedFunctions(file);
			org.junit.jupiter.api.Assertions.assertNotNull(imports);

			var headerResult = com.TheSecureSyndicate.threat_detection_backend.service.StaticAnalysisService.extractHeaderAndSections(file);
			org.junit.jupiter.api.Assertions.assertNotNull(headerResult);
			org.junit.jupiter.api.Assertions.assertNotNull(headerResult.getSections());
		}
	}

	@Test
	void testYaraScanService() {
		org.junit.jupiter.api.Assertions.assertNotNull(yaraScanService);
		boolean verified = yaraScanService.verifyYaraPrerequisites();
		org.junit.jupiter.api.Assertions.assertTrue(verified, "YARA binary and rule files should be verified");

		java.io.File dropper = new java.io.File("uploads/0ce47728-fc59-4878-84d3-27cd451c8397_dropper.exe");
		if (dropper.exists()) {
			var result = yaraScanService.scanFile(dropper.toPath(), "test-binary-1");
			org.junit.jupiter.api.Assertions.assertNotNull(result);
			org.junit.jupiter.api.Assertions.assertTrue(result.isMatched());
			org.junit.jupiter.api.Assertions.assertTrue(result.getMatchedRules().contains("Suspicious_PE_Name"));
		}
	}
}
