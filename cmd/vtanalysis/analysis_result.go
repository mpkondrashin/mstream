package main

type AnalysisResult struct {
	Category      string `json:"category"`
	EngineName    string `json:"engine_name"`
	EngineUpdate  string `json:"engine_update"`
	EngineVersion string `json:"engine_version"`
	Method        string `json:"method"`
	Result        string `json:"result"`
}

/*
type AutoGenerated struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		CreationDate            int `json:"creation_date"`
		CrowdsourcedYaraResults []struct {
			Author      string `json:"author"`
			Description string `json:"description"`
			RuleName    string `json:"rule_name"`
			RulesetID   string `json:"ruleset_id"`
			RulesetName string `json:"ruleset_name"`
			Source      string `json:"source"`
		} `json:"crowdsourced_yara_results"`
		FirstSubmissionDate int `json:"first_submission_date"`
		LastAnalysisDate    int `json:"last_analysis_date"`
		LastAnalysisResults struct {
			ALYac struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"ALYac"`
			Apex struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"APEX"`
			Avg struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"AVG"`
			Acronis struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Acronis"`
			AdAware struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"Ad-Aware"`
			AhnLabV3 struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"AhnLab-V3"`
			Alibaba struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Alibaba"`
			AntiyAVL struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Antiy-AVL"`
			Arcabit struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"Arcabit"`
			Avast struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"Avast"`
			AvastMobile struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Avast-Mobile"`
			Avira struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"Avira"`
			Baidu struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Baidu"`
			BitDefender struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"BitDefender"`
			BitDefenderFalx struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"BitDefenderFalx"`
			BitDefenderTheta struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"BitDefenderTheta"`
			Bkav struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Bkav"`
			CATQuickHeal struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"CAT-QuickHeal"`
			Cmc struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"CMC"`
			ClamAV struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"ClamAV"`
			Comodo struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Comodo"`
			CrowdStrike struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"CrowdStrike"`
			Cybereason struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion interface{} `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Cybereason"`
			Cylance struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Cylance"`
			Cynet struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"Cynet"`
			Cyren struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"Cyren"`
			DrWeb struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"DrWeb"`
			ESETNOD32 struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"ESET-NOD32"`
			Elastic struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Elastic"`
			Emsisoft struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"Emsisoft"`
			FSecure struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"F-Secure"`
			FireEye struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"FireEye"`
			Fortinet struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"Fortinet"`
			GData struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"GData"`
			Gridinsoft struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Gridinsoft"`
			Ikarus struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"Ikarus"`
			Jiangmin struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Jiangmin"`
			K7AntiVirus struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"K7AntiVirus"`
			K7Gw struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"K7GW"`
			Kaspersky struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"Kaspersky"`
			Kingsoft struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Kingsoft"`
			Lionic struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"Lionic"`
			Max struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"MAX"`
			Malwarebytes struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Malwarebytes"`
			MaxSecure struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"MaxSecure"`
			McAfee struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"McAfee"`
			McAfeeGWEdition struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"McAfee-GW-Edition"`
			MicroWorldEScan struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"MicroWorld-eScan"`
			Microsoft struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"Microsoft"`
			NANOAntivirus struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"NANO-Antivirus"`
			Paloalto struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Paloalto"`
			Panda struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Panda"`
			Rising struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"Rising"`
			SUPERAntiSpyware struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"SUPERAntiSpyware"`
			Sangfor struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"Sangfor"`
			SentinelOne struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"SentinelOne"`
			Sophos struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"Sophos"`
			Symantec struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"Symantec"`
			SymantecMobileInsight struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"SymantecMobileInsight"`
			Tachyon struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"TACHYON"`
			Tencent struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"Tencent"`
			Trapmine struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Trapmine"`
			TrendMicro struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"TrendMicro"`
			TrendMicroHouseCall struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"TrendMicro-HouseCall"`
			Trustlook struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Trustlook"`
			Vba32 struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"VBA32"`
			Vipre struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"VIPRE"`
			ViRobot struct {
				Category      string `json:"category"`
				EngineName    string `json:"engine_name"`
				EngineUpdate  string `json:"engine_update"`
				EngineVersion string `json:"engine_version"`
				Method        string `json:"method"`
				Result        string `json:"result"`
			} `json:"ViRobot"`
			Webroot struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Webroot"`
			Yandex struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Yandex"`
			Zillya struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Zillya"`
			Zoner struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion string      `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"Zoner"`
			EGambit struct {
				Category      string      `json:"category"`
				EngineName    string      `json:"engine_name"`
				EngineUpdate  string      `json:"engine_update"`
				EngineVersion interface{} `json:"engine_version"`
				Method        string      `json:"method"`
				Result        interface{} `json:"result"`
			} `json:"eGambit"`
		} `json:"last_analysis_results"`
		LastAnalysisStats struct {
			ConfirmedTimeout int `json:"confirmed-timeout"`
			Failure          int `json:"failure"`
			Harmless         int `json:"harmless"`
			Malicious        int `json:"malicious"`
			Suspicious       int `json:"suspicious"`
			Timeout          int `json:"timeout"`
			TypeUnsupported  int `json:"type-unsupported"`
			Undetected       int `json:"undetected"`
		} `json:"last_analysis_stats"`
		LastModificationDate        int      `json:"last_modification_date"`
		LastSubmissionDate          int      `json:"last_submission_date"`
		Magic                       string   `json:"magic"`
		Md5                         string   `json:"md5"`
		MeaningfulName              string   `json:"meaningful_name"`
		Names                       []string `json:"names"`
		PopularThreatClassification struct {
			PopularThreatCategory []struct {
				Count int    `json:"count"`
				Value string `json:"value"`
			} `json:"popular_threat_category"`
			PopularThreatName []struct {
				Count int    `json:"count"`
				Value string `json:"value"`
			} `json:"popular_threat_name"`
			SuggestedThreatLabel string `json:"suggested_threat_label"`
		} `json:"popular_threat_classification"`
		Reputation      int `json:"reputation"`
		SandboxVerdicts struct {
			BitDamATP struct {
				Category              string   `json:"category"`
				MalwareClassification []string `json:"malware_classification"`
				SandboxName           string   `json:"sandbox_name"`
			} `json:"BitDam ATP"`
		} `json:"sandbox_verdicts"`
		Sha1           string   `json:"sha1"`
		Sha256         string   `json:"sha256"`
		Size           int      `json:"size"`
		Ssdeep         string   `json:"ssdeep"`
		Tags           []string `json:"tags"`
		TimesSubmitted int      `json:"times_submitted"`
		Tlsh           string   `json:"tlsh"`
		TotalVotes     struct {
			Harmless  int `json:"harmless"`
			Malicious int `json:"malicious"`
		} `json:"total_votes"`
		Trid []struct {
			FileType    string  `json:"file_type"`
			Probability float64 `json:"probability"`
		} `json:"trid"`
		TypeDescription string `json:"type_description"`
		TypeExtension   string `json:"type_extension"`
		TypeTag         string `json:"type_tag"`
		UniqueSources   int    `json:"unique_sources"`
		Vhash           string `json:"vhash"`
	} `json:"attributes"`
	Links struct {
		Self string `json:"self"`
	} `json:"links"`
}


*/
