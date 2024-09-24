using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;

namespace elastic.fulltext.sandbox.Models
{
    [Serializable]
    public class OpenRMFProLog
    {
        public OpenRMFProLog () {
            url = new OpenRMFProLogUrl();
            http = new OpenRMFProLogHttp();
            elasticEvent = new OpenRMFProLogEvent();
        }

        [JsonPropertyName("Message")]
        public string message { get; set; }
        [JsonPropertyName("Stacktrace")]
        public string stacktrace { get; set; }
        [JsonPropertyName("RequestHost")]
        public string requestHost { get; set; }
        [JsonPropertyName("RequestURL")]
        public string requestURL { get; set; }
        [JsonPropertyName("Service")]
        public string service { get; set; }
        [JsonPropertyName("Exception")]
        public string exception { get; set; }
        [JsonPropertyName("@timestamp")]
        public DateTimeOffset timestamp { get; set; }
        [JsonPropertyName("Properties")]
        public string properties { get; set; }
        [JsonPropertyName("Logger")]
        public string logger { get; set; }
        [JsonPropertyName("Level")]
        public string level { get; set; }
        [JsonPropertyName("ServiceType")]
        public string serviceType { get; set; }
        [JsonPropertyName("MachineName")]
        public string machineName { get; set; }
        [JsonPropertyName("RequestReferrer")]
        public string requestReferrer { get; set; }

        // objects
        [JsonPropertyName("url")]
        public OpenRMFProLogUrl url { get; set; }

        [JsonPropertyName("http")]
        public OpenRMFProLogHttp http { get; set;}
        
        [JsonPropertyName("event")]
        public OpenRMFProLogEvent elasticEvent { get; set; }

    }

    public class OpenRMFProLogUrl {

        public OpenRMFProLogUrl() {

        }

        [JsonPropertyName("path")]
        public string path { get; set; }
        [JsonPropertyName("port")]
        public int port { get; set; }
        [JsonPropertyName("domain")]
        public string domain { get; set; }
    }

    public class OpenRMFProLogHttp {
        public OpenRMFProLogHttp() {

        }

        [JsonPropertyName("request")]
        public OpenRMFProLogHttpRequest request { get; set; }
        [JsonPropertyName("method")]
        public string method { get; set;}
        [JsonPropertyName("version")]
        public string version { get; set;}
    }

    public class OpenRMFProLogHttpRequest {
        public OpenRMFProLogHttpRequest() { }

        [JsonPropertyName("body")]
        public OpenRMFProLogHttpRequestBody body { get; set;}
    }

    public class OpenRMFProLogHttpRequestBody {
        public OpenRMFProLogHttpRequestBody() { } 

        [JsonPropertyName("bytes")]
        public string bytes { get; set; }
    }

    public class OpenRMFProLogEvent {
        public OpenRMFProLogEvent() {}

        [JsonPropertyName("original")]
        public string original { get; set;}
    }

}