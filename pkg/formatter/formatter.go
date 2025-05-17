package formatter

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/omerimzali/subscan/pkg/probe"
	"github.com/omerimzali/subscan/pkg/scorer"
)

// Format types
const (
	FormatPlain    = "plain"
	FormatJSON     = "json"
	FormatCSV      = "csv"
	FormatHTML     = "html"
	FormatMarkdown = "markdown"
)

// IsValidFormat checks if the provided format is supported
func IsValidFormat(format string) bool {
	switch format {
	case FormatPlain, FormatJSON, FormatCSV, FormatHTML, FormatMarkdown:
		return true
	default:
		return false
	}
}

// SubdomainData represents a simplified data structure for output formatting
type SubdomainData struct {
	Domain        string   `json:"domain"`
	Status        int      `json:"status"`
	ContentLength int64    `json:"content_length"`
	CNAME         string   `json:"cname,omitempty"`
	CloudProvider string   `json:"cloud_provider,omitempty"`
	Score         float64  `json:"score"`
	Tags          []string `json:"tags,omitempty"`
	IsTLS         bool     `json:"is_tls"`
}

// HTMLTemplateData holds data for the HTML template rendering
type HTMLTemplateData struct {
	Title       string
	Date        string
	Count       int
	Subdomains  []SubdomainData
	DomainName  string
	GeneratedBy string
}

// Format converts the analyis results to the specified format
func Format(results []scorer.SubdomainInfo, format string, targetDomain string) (string, error) {
	switch format {
	case FormatPlain:
		return formatPlain(results), nil
	case FormatJSON:
		return formatJSON(results)
	case FormatCSV:
		return formatCSV(results)
	case FormatHTML:
		return formatHTML(results, targetDomain)
	case FormatMarkdown:
		return formatMarkdown(results, targetDomain), nil
	default:
		return "", fmt.Errorf("unsupported format: %s", format)
	}
}

// formatPlain formats the results as plain text
func formatPlain(results []scorer.SubdomainInfo) string {
	var output strings.Builder
	
	for _, info := range results {
		// Format tags
		tags := ""
		if len(info.Tags) > 0 {
			tags = "[" + strings.Join(info.Tags, "][") + "] "
		}
		
		// Format status
		status := "?"
		if info.HTTPStatus > 0 {
			status = fmt.Sprintf("%d", info.HTTPStatus)
		}
		
		// Format size
		size := ""
		if info.ContentLength > 0 {
			sizeKB := info.ContentLength / 1024
			if sizeKB > 0 {
				size = fmt.Sprintf(" (%d KB)", sizeKB)
			} else {
				size = fmt.Sprintf(" (%d bytes)", info.ContentLength)
			}
		}
		
		// Format additional info
		additional := ""
		if info.CloudProvider != "" {
			additional += fmt.Sprintf(" [Cloud: %s]", info.CloudProvider)
		}
		if len(info.CNAMEs) > 0 {
			additional += fmt.Sprintf(" [CNAME: %s]", info.CNAMEs[0])
		}
		
		line := fmt.Sprintf("%s%s [%s]%s%s\n", tags, info.Subdomain, status, size, additional)
		output.WriteString(line)
	}
	
	return output.String()
}

// formatJSON formats the results as JSON
func formatJSON(results []scorer.SubdomainInfo) (string, error) {
	var jsonData []SubdomainData
	
	for _, info := range results {
		cname := ""
		if len(info.CNAMEs) > 0 {
			cname = info.CNAMEs[0]
		}
		
		data := SubdomainData{
			Domain:        info.Subdomain,
			Status:        info.HTTPStatus,
			ContentLength: info.ContentLength,
			CNAME:         cname,
			CloudProvider: info.CloudProvider,
			Score:         info.Score,
			Tags:          info.Tags,
			IsTLS:         info.IsTLS,
		}
		
		jsonData = append(jsonData, data)
	}
	
	jsonBytes, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("error marshaling to JSON: %v", err)
	}
	
	return string(jsonBytes), nil
}

// formatCSV formats the results as CSV
func formatCSV(results []scorer.SubdomainInfo) (string, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	
	// Write header
	header := []string{"Domain", "Status", "ContentLength", "CNAME", "CloudProvider", "Score", "Tags", "IsTLS"}
	if err := writer.Write(header); err != nil {
		return "", fmt.Errorf("error writing CSV header: %v", err)
	}
	
	// Write data rows
	for _, info := range results {
		cname := ""
		if len(info.CNAMEs) > 0 {
			cname = info.CNAMEs[0]
		}
		
		tags := strings.Join(info.Tags, ",")
		isTLS := "false"
		if info.IsTLS {
			isTLS = "true"
		}
		
		row := []string{
			info.Subdomain,
			fmt.Sprintf("%d", info.HTTPStatus),
			fmt.Sprintf("%d", info.ContentLength),
			cname,
			info.CloudProvider,
			fmt.Sprintf("%.2f", info.Score),
			tags,
			isTLS,
		}
		
		if err := writer.Write(row); err != nil {
			return "", fmt.Errorf("error writing CSV row: %v", err)
		}
	}
	
	writer.Flush()
	if err := writer.Error(); err != nil {
		return "", fmt.Errorf("error flushing CSV writer: %v", err)
	}
	
	return buf.String(), nil
}

// formatHTML formats the results as HTML
func formatHTML(results []scorer.SubdomainInfo, targetDomain string) (string, error) {
	var subdomains []SubdomainData
	
	for _, info := range results {
		cname := ""
		if len(info.CNAMEs) > 0 {
			cname = info.CNAMEs[0]
		}
		
		data := SubdomainData{
			Domain:        info.Subdomain,
			Status:        info.HTTPStatus,
			ContentLength: info.ContentLength,
			CNAME:         cname,
			CloudProvider: info.CloudProvider,
			Score:         info.Score,
			Tags:          info.Tags,
			IsTLS:         info.IsTLS,
		}
		
		subdomains = append(subdomains, data)
	}
	
	data := HTMLTemplateData{
		Title:       fmt.Sprintf("Subscan Results for %s", targetDomain),
		Date:        time.Now().Format("2006-01-02 15:04:05"),
		Count:       len(subdomains),
		Subdomains:  subdomains,
		DomainName:  targetDomain,
		GeneratedBy: "Subscan",
	}
	
	var buf bytes.Buffer
	if err := writeHTMLReport(&buf, data); err != nil {
		return "", fmt.Errorf("error generating HTML report: %v", err)
	}
	
	return buf.String(), nil
}

// writeHTMLReport writes an HTML report to the given writer
func writeHTMLReport(w io.Writer, data HTMLTemplateData) error {
	htmlTemplate := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ .Title }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
        }
        h1 {
            color: #2c3e50;
            border-bottom: 2px solid #eaecef;
            padding-bottom: 10px;
        }
        .summary {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px 12px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        tr:hover {
            background-color: #f1f1f1;
        }
        .has-issues {
            background-color: #fff8e1;
        }
        .has-issues td {
            border-left: 3px solid #ffc107;
        }
        .tag {
            display: inline-block;
            padding: 2px 6px;
            margin: 2px;
            border-radius: 3px;
            font-size: 12px;
            background-color: #e0e0e0;
        }
        .tag-200 { background-color: #8bc34a; color: white; }
        .tag-403 { background-color: #ff9800; color: white; }
        .tag-404 { background-color: #f44336; color: white; }
        .tag-500 { background-color: #9c27b0; color: white; }
        .tag-REDIRECT { background-color: #2196f3; color: white; }
        .tag-LARGE { background-color: #009688; color: white; }
        .tag-cloud { background-color: #3f51b5; color: white; }
        footer {
            margin-top: 40px;
            text-align: center;
            font-size: 0.8em;
            color: #777;
        }
    </style>
</head>
<body>
    <h1>{{ .Title }}</h1>
    
    <div class="summary">
        <p><strong>Date:</strong> {{ .Date }}</p>
        <p><strong>Target Domain:</strong> {{ .DomainName }}</p>
        <p><strong>Subdomains Found:</strong> {{ .Count }}</p>
    </div>
    
    <table>
        <thead>
            <tr>
                <th>Domain</th>
                <th>Status</th>
                <th>Size</th>
                <th>CNAME</th>
                <th>Score</th>
                <th>Tags</th>
            </tr>
        </thead>
        <tbody>
            {{ range .Subdomains }}
            <tr>
                <td>{{ if .IsTLS }}<span title="HTTPS Available">🔒</span>{{ end }} {{ .Domain }}</td>
                <td>{{ .Status }}</td>
                <td>{{ if gt .ContentLength 0 }}{{ .ContentLength }} bytes{{ end }}</td>
                <td>{{ if .CloudProvider }}<span class="tag tag-cloud">{{ .CloudProvider }}</span>{{ end }} {{ .CNAME }}</td>
                <td>{{ printf "%.1f" .Score }}</td>
                <td>
                    {{ range .Tags }}
                    <span class="tag 
                        {{- if eq . "200" }} tag-200
                        {{- else if eq . "403" }} tag-403
                        {{- else if eq . "404" }} tag-404
                        {{- else if eq . "500" }} tag-500
                        {{- else if eq . "REDIRECT" }} tag-REDIRECT
                        {{- else if eq . "LARGE" }} tag-LARGE
                        {{- end -}}
                    ">{{ . }}</span>
                    {{ end }}
                </td>
            </tr>
            {{ end }}
        </tbody>
    </table>
    
    <footer>
        <p>Generated by {{ .GeneratedBy }} on {{ .Date }}</p>
    </footer>
</body>
</html>`

	tmpl, err := template.New("html_report").Parse(htmlTemplate)
	if err != nil {
		return err
	}
	
	return tmpl.Execute(w, data)
}

// formatMarkdown formats the results as Markdown
func formatMarkdown(results []scorer.SubdomainInfo, targetDomain string) string {
	var output strings.Builder
	
	// Write header
	output.WriteString(fmt.Sprintf("# Subscan Results for %s\n\n", targetDomain))
	output.WriteString(fmt.Sprintf("**Date:** %s  \n", time.Now().Format("2006-01-02 15:04:05")))
	output.WriteString(fmt.Sprintf("**Target Domain:** %s  \n", targetDomain))
	output.WriteString(fmt.Sprintf("**Subdomains Found:** %d  \n\n", len(results)))
	
	// Table header
	output.WriteString("| Domain | Status | Size | CNAME | Score | Tags |\n")
	output.WriteString("|--------|--------|------|-------|-------|------|\n")
	
	// Table rows
	for _, info := range results {
		cname := ""
		if len(info.CNAMEs) > 0 {
			cname = info.CNAMEs[0]
		}
		
		// TLS indicator
		tlsIndicator := ""
		if info.IsTLS {
			tlsIndicator = "🔒 "
		}
		
		// Format tags
		tags := ""
		if len(info.Tags) > 0 {
			for _, tag := range info.Tags {
				tags += fmt.Sprintf("`%s` ", tag)
			}
		}
		
		// Format size
		size := ""
		if info.ContentLength > 0 {
			sizeKB := info.ContentLength / 1024
			if sizeKB > 0 {
				size = fmt.Sprintf("%d KB", sizeKB)
			} else {
				size = fmt.Sprintf("%d bytes", info.ContentLength)
			}
		}
		
		// Add cloud provider info to cname if available
		if info.CloudProvider != "" {
			cname = fmt.Sprintf("%s (`%s`)", cname, info.CloudProvider)
		}
		
		line := fmt.Sprintf("| %s%s | %d | %s | %s | %.1f | %s |\n",
			tlsIndicator, info.Subdomain, info.HTTPStatus, size, cname, info.Score, tags)
		output.WriteString(line)
	}
	
	// Footer
	output.WriteString("\n\n*Generated by Subscan*\n")
	
	return output.String()
}

// FormatProbeResults formats probe results in the specified format
func FormatProbeResults(results []probe.ProbeResult, format string) (string, error) {
	switch format {
	case FormatJSON:
		return formatProbeResultsJSON(results)
	case FormatCSV:
		return formatProbeResultsCSV(results)
	case FormatHTML:
		return formatProbeResultsHTML(results)
	case FormatMarkdown:
		return formatProbeResultsMarkdown(results), nil
	case FormatPlain:
		return probe.FormatProbeResults(results, true), nil
	default:
		// Format is not supported
		return "", fmt.Errorf("unsupported format for probe results: %s", format)
	}
}

// formatProbeResultsJSON formats probe results as JSON
func formatProbeResultsJSON(results []probe.ProbeResult) (string, error) {
	jsonBytes, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", fmt.Errorf("error marshaling probe results to JSON: %v", err)
	}
	
	return string(jsonBytes), nil
}

// formatProbeResultsCSV formats probe results as CSV
func formatProbeResultsCSV(results []probe.ProbeResult) (string, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	
	// Write header
	header := []string{"Domain", "CNAME", "HTTPStatus", "ContentLength", "IsTakeover", "S3Public", "S3Private", "ExposedFiles", "OpenRedirect", "RedirectURL", "Vulnerabilities", "Tags"}
	if err := writer.Write(header); err != nil {
		return "", fmt.Errorf("error writing CSV header: %v", err)
	}
	
	// Write data rows
	for _, result := range results {
		exposedFiles := strings.Join(result.ExposedFiles, "|")
		vulnerabilities := strings.Join(result.Vulnerabilities, "|")
		tags := strings.Join(result.Tags, "|")
		
		isTakeover := "false"
		if result.IsTakeover {
			isTakeover = "true"
		}
		
		s3Public := "false"
		if result.S3Public {
			s3Public = "true"
		}
		
		s3Private := "false"
		if result.S3Private {
			s3Private = "true"
		}
		
		openRedirect := "false"
		if result.OpenRedirect {
			openRedirect = "true"
		}
		
		row := []string{
			result.Domain,
			result.CNAME,
			fmt.Sprintf("%d", result.HTTPStatus),
			fmt.Sprintf("%d", result.ContentLength),
			isTakeover,
			s3Public,
			s3Private,
			exposedFiles,
			openRedirect,
			result.RedirectURL,
			vulnerabilities,
			tags,
		}
		
		if err := writer.Write(row); err != nil {
			return "", fmt.Errorf("error writing CSV row: %v", err)
		}
	}
	
	writer.Flush()
	if err := writer.Error(); err != nil {
		return "", fmt.Errorf("error flushing CSV writer: %v", err)
	}
	
	return buf.String(), nil
}

// ProbeTemplateData holds data for the HTML probe report template
type ProbeTemplateData struct {
	Title       string
	Date        string
	Count       int
	Results     []probe.ProbeResult
	GeneratedBy string
	Stats       struct {
		Total        int
		Takeovers    int
		S3Issues     int
		ExposedFiles int
		OpenRedirect int
	}
}

// formatProbeResultsHTML formats probe results as HTML
func formatProbeResultsHTML(results []probe.ProbeResult) (string, error) {
	data := ProbeTemplateData{
		Title:       "Subscan Probe Results",
		Date:        time.Now().Format("2006-01-02 15:04:05"),
		Count:       len(results),
		Results:     results,
		GeneratedBy: "Subscan",
	}
	
	// Calculate statistics
	data.Stats.Total = len(results)
	for _, result := range results {
		if result.IsTakeover {
			data.Stats.Takeovers++
		}
		if result.S3Public {
			data.Stats.S3Issues++
		}
		if len(result.ExposedFiles) > 0 {
			data.Stats.ExposedFiles++
		}
		if result.OpenRedirect {
			data.Stats.OpenRedirect++
		}
	}
	
	var buf bytes.Buffer
	if err := writeProbeHTMLReport(&buf, data); err != nil {
		return "", fmt.Errorf("error generating HTML report: %v", err)
	}
	
	return buf.String(), nil
}

// writeProbeHTMLReport writes an HTML report for probe results
func writeProbeHTMLReport(w io.Writer, data ProbeTemplateData) error {
	htmlTemplate := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ .Title }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background-color: #f4f4f4;
            padding: 10px 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        h1 {
            color: #444;
        }
        .stats {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 20px;
        }
        .stat-box {
            background-color: #f8f8f8;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 10px 15px;
            flex: 1;
            min-width: 150px;
            text-align: center;
        }
        .stat-box.warning {
            background-color: #fff3cd;
            border-color: #ffecb5;
        }
        .stat-box h3 {
            margin: 0;
            font-size: 14px;
            font-weight: normal;
        }
        .stat-box p {
            margin: 5px 0 0;
            font-size: 24px;
            font-weight: bold;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 10px;
            border: 1px solid #ddd;
            text-align: left;
        }
        th {
            background-color: #f4f4f4;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        tr:hover {
            background-color: #f1f1f1;
        }
        .has-issues {
            background-color: #fff8e1;
        }
        .has-issues td {
            border-left: 3px solid #ffc107;
        }
        .tag {
            display: inline-block;
            background-color: #e9e9e9;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 12px;
            margin-right: 5px;
            margin-bottom: 3px;
        }
        .tag.warning {
            background-color: #ffd7d7;
        }
        .vuln-list {
            margin: 0;
            padding-left: 20px;
        }
        footer {
            text-align: center;
            margin-top: 30px;
            font-size: 12px;
            color: #777;
        }
    </style>
</head>
<body>
    <header>
        <h1>{{ .Title }}</h1>
        <p>Generated on {{ .Date }} by {{ .GeneratedBy }}</p>
    </header>

    <div class="stats">
        <div class="stat-box">
            <h3>Total Domains</h3>
            <p>{{ .Stats.Total }}</p>
        </div>
        <div class="stat-box {{ if gt .Stats.Takeovers 0 }}warning{{ end }}">
            <h3>Takeover Candidates</h3>
            <p>{{ .Stats.Takeovers }}</p>
        </div>
        <div class="stat-box {{ if gt .Stats.S3Issues 0 }}warning{{ end }}">
            <h3>S3 Bucket Issues</h3>
            <p>{{ .Stats.S3Issues }}</p>
        </div>
        <div class="stat-box {{ if gt .Stats.ExposedFiles 0 }}warning{{ end }}">
            <h3>Exposed Files</h3>
            <p>{{ .Stats.ExposedFiles }}</p>
        </div>
        <div class="stat-box {{ if gt .Stats.OpenRedirect 0 }}warning{{ end }}">
            <h3>Open Redirects</h3>
            <p>{{ .Stats.OpenRedirect }}</p>
        </div>
    </div>

    <h2>Vulnerability Details</h2>
    <table>
        <thead>
            <tr>
                <th>Domain</th>
                <th>Issues</th>
                <th>Details</th>
                <th>Tags</th>
            </tr>
        </thead>
        <tbody>
            {{ range .Results }}
                <tr{{ if or .IsTakeover .S3Public (len .ExposedFiles) .OpenRedirect (len .Vulnerabilities) }} class="has-issues"{{ end }}>
                    <td>{{ .Domain }}</td>
                    <td>
                        <ul class="vuln-list">
                            {{ range .Vulnerabilities }}
                                <li>{{ . }}</li>
                            {{ end }}
                        </ul>
                    </td>
                    <td>
                        {{ if ne .CNAME "" }}
                            <strong>CNAME:</strong> {{ .CNAME }}<br>
                        {{ end }}
                        
                        {{ if gt .HTTPStatus 0 }}
                            <strong>Status:</strong> {{ .HTTPStatus }}<br>
                        {{ end }}
                        
                        {{ if gt .ContentLength 0 }}
                            <strong>Size:</strong> {{ .ContentLength }} bytes<br>
                        {{ end }}
                        
                        {{ if .OpenRedirect }}
                            <strong>Redirect URL:</strong> {{ .RedirectURL }}<br>
                        {{ end }}
                        
                        {{ if len .ExposedFiles }}
                            <strong>Exposed Files:</strong>
                            <ul class="vuln-list">
                                {{ range .ExposedFiles }}
                                    <li>{{ . }}</li>
                                {{ end }}
                            </ul>
                        {{ end }}
                    </td>
                    <td>
                        {{ range .Tags }}
                            <span class="tag {{ if or (eq . "TAKEOVER-CANDIDATE") (eq . "PUBLIC-S3") (eq . "OPEN-REDIRECT") }}warning{{ end }}">{{ . }}</span>
                        {{ end }}
                    </td>
                </tr>
            {{ end }}
        </tbody>
    </table>

    <footer>
        <p>Generated by Subscan on {{ .Date }}</p>
    </footer>
</body>
</html>`

	tmpl, err := template.New("probeReport").Parse(htmlTemplate)
	if err != nil {
		return err
	}
	
	return tmpl.Execute(w, data)
}

// formatProbeResultsMarkdown formats probe results as Markdown
func formatProbeResultsMarkdown(results []probe.ProbeResult) string {
	var md strings.Builder
	
	// Add title and timestamp
	md.WriteString("# Subscan Probe Results\n\n")
	md.WriteString(fmt.Sprintf("Generated on: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	
	// Count statistics
	var takeovers, s3Issues, exposedFiles, openRedirects int
	
	for _, result := range results {
		if result.IsTakeover {
			takeovers++
		}
		if result.S3Public {
			s3Issues++
		}
		if len(result.ExposedFiles) > 0 {
			exposedFiles++
		}
		if result.OpenRedirect {
			openRedirects++
		}
	}
	
	// Add summary
	md.WriteString("## Summary\n\n")
	md.WriteString("| Category | Count |\n")
	md.WriteString("|----------|-------|\n")
	md.WriteString(fmt.Sprintf("| Total domains | %d |\n", len(results)))
	md.WriteString(fmt.Sprintf("| Takeover candidates | %d |\n", takeovers))
	md.WriteString(fmt.Sprintf("| S3 bucket issues | %d |\n", s3Issues))
	md.WriteString(fmt.Sprintf("| Exposed sensitive files | %d |\n", exposedFiles))
	md.WriteString(fmt.Sprintf("| Open redirects | %d |\n", openRedirects))
	
	md.WriteString("\n## Vulnerability Details\n\n")
	
	// List vulnerable domains
	for _, result := range results {
		if len(result.Vulnerabilities) == 0 {
			continue // Skip non-vulnerable domains
		}
		
		md.WriteString(fmt.Sprintf("### %s\n\n", result.Domain))
		
		if result.CNAME != "" {
			md.WriteString(fmt.Sprintf("**CNAME:** %s\n\n", result.CNAME))
		}
		
		if len(result.Vulnerabilities) > 0 {
			md.WriteString("**Vulnerabilities:**\n\n")
			for _, vuln := range result.Vulnerabilities {
				md.WriteString(fmt.Sprintf("- %s\n", vuln))
			}
			md.WriteString("\n")
		}
		
		if len(result.ExposedFiles) > 0 {
			md.WriteString("**Exposed Files:**\n\n")
			for _, file := range result.ExposedFiles {
				md.WriteString(fmt.Sprintf("- %s\n", file))
			}
			md.WriteString("\n")
		}
		
		if result.OpenRedirect {
			md.WriteString(fmt.Sprintf("**Open Redirect URL:** %s\n\n", result.RedirectURL))
		}
		
		if len(result.Tags) > 0 {
			md.WriteString(fmt.Sprintf("**Tags:** %s\n\n", strings.Join(result.Tags, ", ")))
		}
		
		md.WriteString("---\n\n")
	}
	
	return md.String()
} 