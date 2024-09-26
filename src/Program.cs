using elastic.fulltext.sandbox.Models;
using Elastic.Clients.Elasticsearch;
using Elastic.Clients.Elasticsearch.Aggregations;
using Elastic.Clients.Elasticsearch.Nodes;
using Elastic.Clients.Elasticsearch.QueryDsl;
using Elastic.Transport;

namespace elastic.fulltext.sandbox;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Starting Elastic Client");
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("CLOUDURL")) || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("APIKEY")) && 
        string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ELASTICUSER")) || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ELASTICPWD"))) {
            Console.WriteLine("Invalid Cloud or API Key or login/pwd environment variables");
            Environment.Exit(1);
        }

        // var settings = new ElasticsearchClientSettings(new Uri(Environment.GetEnvironmentVariable("CLOUDURL")))
        //     .CertificateFingerprint("E5560F4D0046EA4D02BDB4197473347DFAA76938AFD13281C7C44B2009B08A24")
        //     .Authentication(new ApiKey(Environment.GetEnvironmentVariable("APIKEY")));
        //     //.Authentication(new BasicAuthentication("dale.bingham@soteriasoft.com","1qaz2wsx#EDC$RFV"));

        var settings = new ElasticsearchClientSettings(new Uri("http://192.168.40.101:9200"))
            .Authentication(new BasicAuthentication(Environment.GetEnvironmentVariable("ELASTICUSER"), 
                Environment.GetEnvironmentVariable("ELASTICPWD")));

        var client = new ElasticsearchClient(settings);

        if (client == null) {
            Console.WriteLine("Elastic Connection Failed");
            Environment.Exit(1);
        }

        #region Local ELK Stack Logs
        // var response = client.SearchAsync<OpenRMFProLog>(s => s.Index("logs-openrmfpro-2024.09.*")
        //     .From(0).Size(100)).GetAwaiter().GetResult();
        // .Query(q => q.MatchAll(z => )));
        //.Query(q => q.Match(m => m.Field("log.Guid").Query("d8bb9004-7cb1-4594-8c93-80135a8b736c"))));
        // if (response.IsValidResponse)
        // {
        //     List<OpenRMFProLog> resultLogs = response.Documents.ToList();
        //     Console.WriteLine("Results " + resultLogs.Count.ToString()  + " Documents");
        // } 
        // else {
        //     Console.WriteLine("Invalid Response. " + response.DebugInformation);
        // }
        #endregion

        #region Load ELK Data
        // // load sample data
        // List<VulnerabilityReport> sampleData = Classes.InitialData.Load();
        // // save the data into the ELK mapping correctly
        // var batchSize = 500;
        // var processed = 0;
        // var hasNextBatch = true;

        // while(hasNextBatch) 
        // {
        //     var batch = sampleData.Skip(processed).Take(batchSize).ToList();
        //     //var indexManyResponse = client.IndexManyAsync<VulnerabilityReport>(sampleData);
        //     var asyncIndexResponse = client.BulkAsync(z => z.Index("openrmfpro-checklists").IndexMany(batch)).GetAwaiter().GetResult();
        //     processed += batch.Count;
        //     hasNextBatch = batch.Count == batchSize; // did it take them all and fill it up to 500
        // }
        
        // Console.WriteLine("Check the ELK Stack for indexing on openrmfpro-checklist");
        #endregion

        #region Search ELK Data
        string searchTerms = "windows AND firewall AND policy";
        var response = client.SearchAsync<VulnerabilityReport>(s => s.Index("openrmfpro-checklists")
            .Query(z => z.QueryString(x => x.Query(searchTerms)))
            .From(0).Size(100)).GetAwaiter().GetResult();
        // .Query(q => q.MatchAll(z => )));
        if (response != null && response.IsValidResponse) {
            Console.WriteLine("Hits: " + response.Hits.Count.ToString());
        }
        #endregion

    }
}
