using System;
using System.Text;
using System.IO;
using System.Xml;
using System.Collections.Generic;
using Newtonsoft.Json;
using System.Linq;

using elastic.fulltext.sandbox.Models;
// using elastic.fulltext.sandbox.Models.Compliance;
// using openrmfpro_api_artifact.Models.PatchData;
// using openrmfpro_api_artifact.Models.Readiness;
// using elastic.fulltext.sandbox.Models.VulnerabilityScan;
// using elastic.fulltext.sandbox.Data;

namespace elastic.fulltext.sandbox.Classes
{

    /// <summary>
    /// This loads sample data into the ELK database.
    /// </summary>
    public static class InitialData {

        public static List<VulnerabilityReport> Load() {
            Console.WriteLine("Load Sample Data");

            var path = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) + "/samples/";

            // get the list of ******.ckl checklist files in here
            string[] filenames = Directory.GetFiles(path,"*.ckl");
            string checklistData = "";
            string artifactId = "";
            string systemGroupId ="";
            string systemTitle = "Full Text Search Package";
            string systemKey = "full-text-searching";
            bool bWebDBApp = false;
            string site = "";
            string instance = "";
            List<VulnerabilityReport> defaultArtifacts = new List<VulnerabilityReport>();
            CHECKLIST tmpChecklist;

            try {
                foreach (string checklistFile in filenames) {
                    // now load the data file by file
                    using (var reader = File.OpenText(checklistFile))
                    {
                            checklistData = reader.ReadToEnd();  
                    }
                    // get rid of extra characters
                    checklistData = CleanUpData(checklistData);
                    // make a CHECKLIST
                    tmpChecklist = LoadChecklist(checklistData);
                    // parse into
                    if (tmpChecklist != null) {
                            VulnerabilityReport vulnRecord; // put the individual record into
                            artifactId = Guid.NewGuid().ToString();

                            // v2.10.01 for web or database
                            // we only need to figure this out one time
                            if (!string.IsNullOrWhiteSpace(tmpChecklist.ASSET.WEB_OR_DATABASE) && tmpChecklist.ASSET.WEB_OR_DATABASE == "true") {
                                bWebDBApp = true;                                
                                if (!string.IsNullOrWhiteSpace(tmpChecklist.ASSET.WEB_DB_SITE))
                                    site = tmpChecklist.ASSET.WEB_DB_SITE.Trim();
                                if (!string.IsNullOrWhiteSpace(tmpChecklist.ASSET.WEB_DB_INSTANCE))
                                     instance = tmpChecklist.ASSET.WEB_DB_INSTANCE.Trim();
                            }

                            foreach (VULN vulnerability in tmpChecklist.STIGS.iSTIG.VULN) {
                                // grab pertinent information
                                vulnRecord = new VulnerabilityReport();
                                vulnRecord.systemGroupId = systemGroupId;
                                vulnRecord.systemKey = systemKey;
                                vulnRecord.systemTitle = systemTitle;
                                vulnRecord.artifactId = artifactId;
                                vulnRecord.created = DateTime.Now;
                                vulnRecord.createdBy = Guid.Parse("11111111-1111-1111-1111-111111111111");
                                vulnRecord.createdByName = "SYSTEM";
                                vulnRecord.version = 1;
                                vulnRecord.deleted = false;
                                // generated above just use the data
                                vulnRecord.isWebDatabaseApplication = bWebDBApp;
                                vulnRecord.webDatabaseApplicationSite = site;
                                vulnRecord.webDatabaseApplicationInstance = instance;

                                vulnRecord.vulnid = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Vuln_Num").FirstOrDefault().ATTRIBUTE_DATA;

                                // get the hostname from the ASSET record
                                if (!string.IsNullOrEmpty(tmpChecklist.ASSET.HOST_NAME)) 
                                    vulnRecord.hostname = tmpChecklist.ASSET.HOST_NAME;
                                else 
                                    vulnRecord.hostname = "Unknown";

                                // start getting the vulnerability detailed information
                                vulnRecord.vulnid = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Vuln_Num").FirstOrDefault().ATTRIBUTE_DATA;
                                vulnRecord.checklistVersion = tmpChecklist.STIGS.iSTIG.STIG_INFO.SI_DATA.Where(x => x.SID_NAME == "version").FirstOrDefault().SID_DATA;
                                vulnRecord.checklistRelease = tmpChecklist.STIGS.iSTIG.STIG_INFO.SI_DATA.Where(x => x.SID_NAME == "releaseinfo").FirstOrDefault().SID_DATA;
                                vulnRecord.checklistType = tmpChecklist.STIGS.iSTIG.STIG_INFO.SI_DATA.Where(x => x.SID_NAME == "title").FirstOrDefault().SID_DATA;
                                if (!string.IsNullOrEmpty(vulnRecord.checklistType)) {
                                    vulnRecord.checklistTypeSanitized = SanitizeChecklistType(vulnRecord.checklistType);
                                }
                                if (!string.IsNullOrEmpty(vulnRecord.checklistRelease)) {
                                    vulnRecord.checklistRelease = SanitizeChecklistRelease(vulnRecord.checklistRelease);
                                }
                                vulnRecord.comments = vulnerability.COMMENTS;
                                vulnRecord.details = vulnerability.FINDING_DETAILS;
                                vulnRecord.checkContent = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Check_Content").FirstOrDefault().ATTRIBUTE_DATA;                                
                                vulnRecord.discussion = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Vuln_Discuss").FirstOrDefault().ATTRIBUTE_DATA;
                                vulnRecord.fixText = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Fix_Text").FirstOrDefault().ATTRIBUTE_DATA;
                                vulnRecord.ruleTitle = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Rule_Title").FirstOrDefault().ATTRIBUTE_DATA;
                                vulnRecord.severity = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Severity").FirstOrDefault().ATTRIBUTE_DATA;
                                vulnRecord.severityOverride = vulnerability.SEVERITY_OVERRIDE;
                                vulnRecord.severityJustification = vulnerability.SEVERITY_OVERRIDE;
                                vulnRecord.ruleId = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Rule_ID").FirstOrDefault().ATTRIBUTE_DATA;
                                vulnRecord.ruleVersion = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Rule_Ver").FirstOrDefault().ATTRIBUTE_DATA;
                                vulnRecord.groupTitle = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Group_Title").FirstOrDefault().ATTRIBUTE_DATA;
                                vulnRecord.status = vulnerability.STATUS;
                                // get all the list of CCIs
                                foreach(STIG_DATA stig in vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "CCI_REF").ToList()) {
                                    // add each one of these, from 0 to N of them
                                    if (!string.IsNullOrEmpty(stig.ATTRIBUTE_DATA)) vulnRecord.cciList.Add(stig.ATTRIBUTE_DATA);
                                }

                                defaultArtifacts.Add(vulnRecord); // add it to the listing
                            } // for each VULN record
                    }
                
                }
            } catch (Exception ex) {
                Console.WriteLine(string.Format("SampleData.Load() Checklist Error: {0}", ex.Message));
            }

            return defaultArtifacts;
        }

        /// <summary>
        /// Remove extra stuff from the Data
        /// </summary>
        private static string CleanUpData (string rawdata) {
            return rawdata.Replace("\t","").Replace(">\n<","><");
        }

        public static CHECKLIST LoadChecklist(string rawChecklist) {
            CHECKLIST myChecklist = new CHECKLIST();
            rawChecklist = rawChecklist.Replace("\t","");
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(rawChecklist);
            XmlNodeList assetList = xmlDoc.GetElementsByTagName("ASSET");
            XmlNodeList vulnList = xmlDoc.GetElementsByTagName("VULN");
            XmlNodeList stiginfoList = xmlDoc.GetElementsByTagName("STIG_INFO");
            // ensure all three are valid otherwise this XML is junk
            if (assetList != null && stiginfoList != null && vulnList != null) {
                // fill in the ASSET listing
                if (assetList.Count >= 1)
                    myChecklist.ASSET = getAssetListing(assetList.Item(0));
                // now get the STIG_INFO Listing
                if (stiginfoList.Count >= 1)
                    myChecklist.STIGS.iSTIG.STIG_INFO = getStigInfoListing(stiginfoList.Item(0));
                // now get the VULN listings until the end!
                if (vulnList.Count > 0) {
                    myChecklist.STIGS.iSTIG.VULN = getVulnerabilityListing(vulnList);
                }
            }            
            return myChecklist;
        }

        private static ASSET getAssetListing(XmlNode node) {
            ASSET asset = new ASSET();
            foreach (XmlElement child in node.ChildNodes)
            {
                switch (child.Name) {
                    case "ROLE":
                        asset.ROLE = child.InnerText;
                        break;
                    case "ASSET_TYPE":
                        asset.ASSET_TYPE = child.InnerText;
                        break;
                    case "MARKING": 
                        asset.MARKING = child.InnerText;
                        break;
                    case "HOST_NAME":
                        asset.HOST_NAME = child.InnerText;
                        break;
                    case "HOST_IP":
                        asset.HOST_IP = child.InnerText;
                        break;
                    case "HOST_MAC":
                        asset.HOST_MAC = child.InnerText;
                        break;
                    case "HOST_FQDN":
                        asset.HOST_FQDN = child.InnerText;
                        break;
                    case "TECH_AREA":
                        asset.TECH_AREA = child.InnerText;
                        break;
                    case "TARGET_KEY":
                        asset.TARGET_KEY = child.InnerText;
                        break;
                    case "WEB_OR_DATABASE":
                        asset.WEB_OR_DATABASE = child.InnerText;
                        break;
                    case "WEB_DB_SITE":
                        asset.WEB_DB_SITE = child.InnerText;
                        break;
                    case "WEB_DB_INSTANCE":
                        asset.WEB_DB_INSTANCE = child.InnerText;
                        break;
                }
            }
            return asset;
        }

        private static STIG_INFO getStigInfoListing(XmlNode node) {
            STIG_INFO info = new STIG_INFO();
            SI_DATA data; // used for the name/value pairs

            // cycle through the children in STIG_INFO and get the SI_DATA
            foreach (XmlElement child in node.ChildNodes) {
                // get the SI_DATA record for SID_DATA and SID_NAME and then return them
                // each SI_DATA has 2
                data = new SI_DATA();
                foreach (XmlElement siddata in child.ChildNodes) {
                    if (siddata.Name == "SID_NAME")
                        data.SID_NAME = siddata.InnerText;
                    else if (siddata.Name == "SID_DATA")
                        data.SID_DATA = siddata.InnerText;
                }
                info.SI_DATA.Add(data);
            }            
            return info;
        }

        private static List<VULN> getVulnerabilityListing(XmlNodeList nodes) {
            List<VULN> vulns = new List<VULN>();
            VULN vuln;
            STIG_DATA data;
            foreach (XmlNode node in nodes) {
                vuln = new VULN();
                if (node.ChildNodes.Count > 0) {
                    foreach (XmlElement child in node.ChildNodes.OfType<XmlElement>()) {
                        data = new STIG_DATA();
                        if (child.Name == "STIG_DATA") {
                            foreach (XmlElement stigdata in child.ChildNodes) {
                                if (stigdata.Name == "VULN_ATTRIBUTE")
                                    data.VULN_ATTRIBUTE = stigdata.InnerText;
                                else if (stigdata.Name == "ATTRIBUTE_DATA")
                                    data.ATTRIBUTE_DATA = stigdata.InnerText;
                            }
                            vuln.STIG_DATA.Add(data);
                        }
                        else {
                            // switch on the fields left over to fill them in the VULN class 
                            switch (child.Name) {
                                case "STATUS":
                                    vuln.STATUS = child.InnerText;
                                    break;
                                case "FINDING_DETAILS":
                                    vuln.FINDING_DETAILS = child.InnerText;
                                    break;
                                case "COMMENTS":
                                    vuln.COMMENTS = child.InnerText;
                                    break;
                                case "SEVERITY_OVERRIDE":
                                    vuln.SEVERITY_OVERRIDE = child.InnerText;
                                    break;
                                case "SEVERITY_JUSTIFICATION":
                                    vuln.SEVERITY_JUSTIFICATION = child.InnerText;
                                    break;
                            }
                        }
                    }
                }
                vulns.Add(vuln);
            }
            return vulns;
        }

        /// <summary>
        /// Clean up the Checklist Type / STIG Type string/title and save the shortened one
        /// </summary>
        /// <param name="checklistType">The checklist type title read from the CKL XML file</param>
        /// <returns>
        /// A shortened cleaned-up Checklist Type string.
        /// </returns>
        public static string SanitizeChecklistType(string checklistType) {
            string myType = checklistType;
            myType = myType.Replace("MS Windows","Windows")
                .Replace("SCAP Benchmark","").Replace(" SCAP","").Replace("Cisco IOS-XE","Cisco IOS XE").Replace("Cisco NX-OS", "Cisco NX OS")
                .Replace("Cisco IOS-XR","Cisco IOS XR").Replace("Microsoft Windows","Windows").Replace("Microsoft Windows Defender", "Microsoft Defender")
                .Replace("Windows Defender", "Microsoft Defender").Replace("Windows Server 2012 MS", "Windows Server 2012/2012 R2 Member Server")
                .Replace("Windows Firewall with Advanced Security", "Windows Defender Firewall with Advanced Security")
                .Replace("Microsoft Windows Defender Firewall with Advanced Security", "Windows Defender Firewall with Advanced Security")
                .Replace("Microsoft Defender Firewall with Advanced Security", "Windows Defender Firewall with Advanced Security")
                .Replace("Security Technical Implementation Guide", "STIG").Replace("Windows 7", "WIN 7").Replace("Windows 8", "WIN 8")
                .Replace("Windows 10", "WIN 10").Replace("Windows 11", "WIN 11").Replace("Windows Server", "WIN SVR").Replace("Windows 2008", "WIN 2008")
                .Replace("Application Security and Development", "ASD").Replace("Windows 2012", "WIN 2012")
                .Replace("Microsoft Internet Explorer", "MSIE").Replace("Red Hat Enterprise Linux", "REL").Replace("MS SQL Server", "MSSQL")
                .Replace("Server", "SVR").Replace("Workstation", "WRK").Trim();

            return myType;
        }

        /// <summary>
        /// Clean up the Checklist Release / STIG Release string/title and save the shortened one
        /// </summary>
        /// <param name="checklistRelease">The checklist release read from the CKL XML file</param>
        /// <returns>
        /// A shortened cleaned-up Checklist Release string.
        /// </returns>
        public static string SanitizeChecklistRelease(string checklistRelease) {
            string myRelease = checklistRelease;
            myRelease = myRelease.Replace("Release: ", "R").Replace("Benchmark Date:","dated");

            return myRelease;
        }
    }
}