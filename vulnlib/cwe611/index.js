var parser = require('libxmljs');

class cwe611 {

    static vulnID00001(vinput) {
        let data;
        try { 
            var doc = parser.parseXml(vinput.vinput, {noent: true}); // {"category": "XXE", "true_positive": true, "cwe": 611, "location": { "arg_index": 0, "start_line": 8, "end_line": 8 }}
            for (var i = 0; i < doc.childNodes().length;i++) {
              data += doc.child(i).toString();
            }
        } catch(e) {
            console.log('Error:', e.stack);
        }
        return data
    }
}

module.exports = cwe611