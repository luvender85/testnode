var fs = require('fs');

class cwe22 {
    static vulnID00001(vinput) {
        let data;
        try {
            data = fs.readFileSync(vinput.vinput, 'utf8'); // {"category": "pathtrav", "true_positive": true, "cwe": 22, "location": { "arg_index": 0, "start_line": 7, "end_line": 7 }}
        } catch(e) {
            console.log('Error:', e.stack);
        }
        return data
    }
}

module.exports = cwe22