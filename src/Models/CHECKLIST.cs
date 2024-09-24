// This is one large class to mimic the exact structure of the 
// Checklist v1 and v2 XML from the DISA STIG Viewer. If you take 
// the XML and do the XSD formatting against it a few times you can 
// get to a scaled down of the class like below.

using System.Collections.Generic;
using System.Xml.Serialization;

namespace elastic.fulltext.sandbox.Models
{
    public class CHECKLIST {

        public CHECKLIST (){
            ASSET = new ASSET();
            STIGS = new STIGS();
        }

        public ASSET ASSET { get; set; }
        public STIGS STIGS { get; set; }
    }

    public class ASSET {

        public ASSET (){

        }

		public string ROLE { get; set; }
		public string ASSET_TYPE { get; set; }
		public string HOST_NAME { get; set; }
        public string MARKING { get; set; }
		public string HOST_IP { get; set; }
		public string HOST_MAC { get; set; }
		public string HOST_FQDN { get; set; }
		public string TECH_AREA { get; set; }
		public string TARGET_KEY { get; set; }
		public string WEB_OR_DATABASE { get; set; }
		public string WEB_DB_SITE { get; set; }
		public string WEB_DB_INSTANCE { get; set; }
    }

     public class SI_DATA {

        public SI_DATA (){

        }

        public string SID_NAME { get; set;}
        public string SID_DATA { get; set; }
    }

    public class STIGS {

        public STIGS (){
            iSTIG = new iSTIG();
        }

        public iSTIG iSTIG { get; set; }
    }

    public class iSTIG {

        public iSTIG (){
            STIG_INFO = new STIG_INFO();
            VULN = new List<VULN>();
        }

        public STIG_INFO STIG_INFO { get; set; }

        [XmlElement("VULN")]
        public List<VULN> VULN { get; set; }
    }

    public class STIG_DATA {

        public STIG_DATA (){

        }

		public string VULN_ATTRIBUTE { get; set; }
	    public string ATTRIBUTE_DATA { get; set;}
    }

    public class STIG_INFO {

        public STIG_INFO (){
            SI_DATA = new List<SI_DATA>();
        }

        [XmlElement("SI_DATA")]
        public List<SI_DATA> SI_DATA { get; set;}
    }

    public class VULN {

        public VULN (){
            STIG_DATA = new List<STIG_DATA>();
        }

        [XmlElement("STIG_DATA")]
        public List<STIG_DATA> STIG_DATA { get; set;}
		public string STATUS { get; set;}
		public string FINDING_DETAILS { get; set;}
		public string COMMENTS { get; set;}
		public string SEVERITY_OVERRIDE { get; set;}
		public string SEVERITY_JUSTIFICATION { get; set;}
    }

}