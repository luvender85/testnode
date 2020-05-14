const Controller = require('./Controller');

class Cwe918Controller {
  constructor(Service) {
    this.service = Service;
  }

  async cwe918vid00001(request, response) {
    await Controller.handleRequest(request, response, this.service.cwe918vid00001);
  }

  async cwe918vid00002(request, response) {
    await Controller.handleRequest(request, response, this.service.cwe918vid00002);
  }

}

module.exports = Cwe918Controller;
