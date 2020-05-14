const { exec } = require("child_process");

class cwe78 {

    static async vulnID00001(vinput) {
        let data = new Promise((resolve, reject) => {
          exec(vinput.vinput, (error, stdout, stderr) => { // {"category": "os command injection", "true_positive": true, "cwe": 78, "location": { "arg_index": 0, "start_line": 7, "end_line": 20 }}
                if (error) {
                    console.log(`error: ${error.message}`)
                    reject(`error: ${error.message}`)
                    return
                }
                if (stderr) {
                    console.log(`stderr: ${stderr}`)
                    reject(`stderr: ${stderr}`)
                    return;
                }
                resolve(stdout)
            })
        })
        return data
    }
}

module.exports = cwe78