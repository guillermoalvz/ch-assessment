package scanner

// Options defines authentication profiles and cloud scopes for a scan.
type Options struct {
	AWSRegion         string
	AWSRegions        []string
	AWSProfile        string
	GCPProject        string
	AzureSubscription string
}
