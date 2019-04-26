let svg = d3.select('svg').attr('width', 900).attr('height', 500);
let force = d3.layout.force()
    .distance(300)
    .charge(-800)
    .size([900, 500]);
let nodes = [];

function refreshGraph(data) {
    if ($('#ops option:selected').attr('value') == '') // requires selected operation
        return;
    if(nodes.length > 0) // only build this graphic once
        return;

    let d = JSON.parse(JSON.stringify(data));
    let hosts = d.chosen.network.hosts;
    let startHost = d.chosen.start_host.hostname;
    for(let i =0; i<hosts.length; i++) {
        let stroke = "black";
        if(hosts[i].hostname == startHost)
            stroke = "orange";
        nodes.push({"hostname": hosts[i].hostname, "stroke": stroke});
    }
    applyUpdates(nodes);
}

function applyUpdates(nodes) {
    force.nodes(nodes).start();
    let node = svg.selectAll(".node")
        .data(nodes)
        .enter().append("g")
        .call(force.drag);
    node.append("circle")
        .style("fill", "white")
        .style("stroke", function(d) { return d.stroke; })
        .style("stroke-width", "5px")
        .attr("r", "55");
    node.append("text")
        .style("font-size", "12px")
        .style("text-anchor", "middle")
        .text(function (d) {
            return d.hostname
        });
    force.on("tick", function () {
        node.attr("transform", function (d) {
            return "translate(" + d.x + "," + d.y + ")";
        });
    });
}