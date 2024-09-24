using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;

namespace elastic.fulltext.sandbox.Models
{
    [Serializable]
    public class ElasticLog
    {
        public ElasticLog () {
            host = new ElasticHost();
            elasticEvent = new ElasticEvent();
        }

        [JsonPropertyName("@timestamp")]
        public DateTimeOffset timestamp { get; set; }
        [JsonPropertyName("host")]
        public ElasticHost host { get; set; }

        [JsonPropertyName("event")]
        public ElasticEvent elasticEvent { get; set; }

        [JsonPropertyName("message")]
        public string message { get; set; }
    }

    public class ElasticHost {
        public ElasticHost() {
            ip = new List<string>();
            mac = new List<string>();
        }

        [JsonPropertyName("hostname")]
        public string hostname { get; set; }
        [JsonPropertyName("ip")]
        public List<string> ip { get; set; }
        [JsonPropertyName("name")]
        public string name { get; set; }
        [JsonPropertyName("id")]
        public string id { get; set; }
        [JsonPropertyName("mac")]
        public List<string> mac { get; set; }
        [JsonPropertyName("architecture")]
        public string architecture { get; set; }
    }

    public class ElasticEvent {
        public ElasticEvent() {

        }

        [JsonPropertyName("code")]
        public string code { get; set; }
        [JsonPropertyName("kind")]
        public string kind { get; set; }
        [JsonPropertyName("module")]
        public string module { get; set; }
        [JsonPropertyName("created")]
        public DateTimeOffset created { get; set; }
        [JsonPropertyName("action")]
        public string action { get; set; }
        [JsonPropertyName("id")]
        public string id { get; set; }
        [JsonPropertyName("category")]
        public List<string> category { get; set; }
        [JsonPropertyName("dataset")]
        public string dataset { get; set; }
        [JsonPropertyName("outcome")]
        public string outcome { get; set; }

    }
}