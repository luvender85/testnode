const http = require('http')

class cwe918 {
    static async vulnID00001(vinput) {
        let data = await new Promise((resolve, reject) => {
            http.get(vinput.vinput, res => { // {"category": "SSRF", "true_positive": true, "cwe": 918, "location": { "arg_index": 0, "start_line": 6, "end_line": 12 }}
              res.setEncoding('utf8')
              let body = ''
              res.on('data', chunk => body += chunk)
              res.on('end', () => resolve(body))
            }).on('error', reject)
          });
        return data
    }

    static async vulnID00002(vinput) {
        let data = await new Promise((resolve, reject) => {
            http.get('http'+vinput.vinput, res => { // {"category": "SSRF", "true_positive": true, "cwe": 918, "location": { "arg_index": 0, "start_line": 18, "end_line": 24 }}
              res.setEncoding('utf8')
              let body = ''
              res.on('data', chunk => body += chunk)
              res.on('end', () => resolve(body))
            }).on('error', reject)
          });
        return data
    }

}

module.exports = cwe918