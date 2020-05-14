
class cwe79 {

    static vulnID00001(vinput) {
        let data;
        try {
            data = "<html><head></head><body>You entered: "+vinput.vinput+"</body></html>"; // {"category": "XSS", "true_positive": true, "cwe": 79, "location": { "arg_index": 1, "start_line": 7, "end_line": 7 }}
        } catch(e) {
            console.log('Error:', e.stack);
        }
        return data
    }
}

module.exports = cwe79