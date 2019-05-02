let planner_interval = setInterval(refresh, 30000);
let networks_by_id = {};
let adversaries_by_id = {};
let steps_by_id = {};
let domains_by_id = {};
let provided_by = {};
let ignore_predicate = new Set(["has_property", "has_member", "defines_property"]);

function isDuplicateName(type, name, objs){
    let duplicateNames = Object.keys(objs).filter(function(key){
        return objs[key].name.toLowerCase() == name.toLowerCase();
    });
    if(duplicateNames.length){ alert(type + " with the specified name already exists.");}
    return duplicateNames.length > 0;
}

function handleNetworkFormSubmit(e){
    e.preventDefault();
    let networkForm = $('#network-add-form').is(':visible') ? $('#network-add-form') : $('#network-select-form');
    let hosts = $.map($('#hostTbl').DataTable().rows('.selected').data(), function (item) { return item[2];});
    if(hosts.length == 0){ alert("You need to select some hosts!"); return;}
    let domains = $.map($('#hostTbl').DataTable().rows('.selected').data(), function (item) { return item[3]; });
    if(new Set(domains).size > 1) { alert("You can only create a network out of one domain."); return;}
    let netName = $("#networkNewName").val();
    if(isDuplicateName('A network', netName, networks_by_id)) return;
    let postData = {"name": netName, "domain": domains[0], "hosts": hosts, "index": "network"};

    $.ajax({
        type: networkForm.attr('method'),
        url: networkForm.attr('action'),
        data: JSON.stringify(postData),
        success: function (data) {
            if(data['id']){
                $("#networkNewName").val('');
                $("<option/>", {id: "network-" + data['id'], value: data['id']}).text(netName).appendTo("#networks");
                $("<option/>", {id: "op-network-" + data['id'], value: data['id']}).text(netName).appendTo("#op-network");
                postData['id'] = data['id'];
                for(let domain_id  in domains_by_id){
                    if(domains_by_id[domain_id]['name'] == postData['domain']){
                        postData['domain'] = domain_id;
                        break;
                    }
                }
                delete postData['index'];
                networks_by_id[data['id']] = postData;
                $('#networks').val(data['id']);
                handleNetworkViewModeAction();
                location.reload(true);
            }
            flash('flash-network', data['msg']);
        },
    });
}

function handleAdversaryFormSubmit(e){
    e.preventDefault();
    let advForm = $('#adv-add-form').is(':visible') ? $('#adv-add-form') : $('#adv-select-form');
    let ary = [];
    for(let test of document.getElementById("chosenAdvSteps").getElementsByTagName("li")) { ary.push(test.getAttribute("step"));}
    if(ary.length == 0){alert("An adversary profile must contain at least one step."); return; }
    let advId = $('#adversaries option:selected').attr('value');
    let advName = $("#advNewName").val();
    if(isDuplicateName('An adversary', advName, adversaries_by_id)) return;
    let advExfilMethod = $('#exfil_method').val().trim();
    let advExfilPort = $('#exfil_port').val().trim();
    if(advExfilPort && (!Number.isInteger(Number(advExfilPort)) || Number(advExfilPort) < 1 || Number(advExfilPort) > 65535)){
        alert("The exfil port must be a valid port number between 1-65535.")
        return;
    }
    if($("#missingAdvStepsReqs li").length > 0){
        alert("Missing step dependencies!");
        return;
    }
    let advExfilAddress = $('#exfil_address').val().trim();
    let artifactList = $('#artifactlists').val();
    (artifactList) ? artifactList = [artifactList] : artifactList = [];
    let adversary = {"name": advName, "steps": ary, "index": "adversary", "exfil_method": advExfilMethod,
                "exfil_address": advExfilAddress, "exfil_port": advExfilPort, "artifact_list": artifactList};
    $.ajax({
        type: advForm.attr('method'),
        url: advForm.attr('action'),
        data: JSON.stringify(adversary),
        success: function (data) {
            if(data['id']){
                $('#chosenAdvSteps').empty()
                $("#advNewName").val('');
                $("<option/>", {id: "adv-" + data['id'], value: data['id']}).text(advName).appendTo("#adversaries");
                $("<option/>", {id: "op-adv-" + data['id'], value: data['id']}).text(advName).appendTo("#op-adv");
                delete adversary['index'];
                adversary["protected"] = null;
                adversary['id'] = data['id'];
                adversaries_by_id[data['id']] = adversary;
                $('#adversaries').val(data['id']);
                displayAdversary();
            }
            flash('flash-adversary', data["msg"]);
        },
    });
}

function handleOperationsFormSubmit(e){
    e.preventDefault();
    let opForm = $('#op-form');
    let data = opForm.serialize();
    $.ajax({
        type: opForm.attr('method'),
        url: opForm.attr('action'),
        data: opForm.serialize(),
        success: function (data) {
            let opName = $("#opName").val();
            $("#ops").append(new Option(opName, data["id"]));
            flash('flash-operation', data['msg']);
        },
    });
}

function handleDeleteNetworkAction(){
    let networkId = $('#networks option:selected').attr('value');
    $.ajax({
       url: '/plugin/adversary/gui',
       type: 'DELETE',
       data: {'index':'network', 'id':networkId},
       success:function(data) {
           ["#network-", "#op-network-"].forEach(elem => { $(elem + networkId).remove();});
           flash('flash-network', data);
           delete networks_by_id[networkId];
           Object.keys(networks_by_id).length ? handleNetworkViewModeAction() : showNetworkAddMode();
       }
    });
}

function handleOperationNetworkChange(e){
    let reqElems = ['[name=start_user]', '[name=start_password]' ];
    let selectedNetId = $('#op-network option:selected').val();
    let domain = networks_by_id[selectedNetId].domain;
    domain = domains_by_id[domain];
    if(domain.is_simulated) {
        reqElems.forEach(function(elem){
            $(elem).prop('required', false).prop('readonly', true).css('opacity', '0.5').val('sim\\sim');
        });
        $('#op-start-type option:contains("bootstrap")').prop('selected',true);
        $('#op-start-type').prop('readonly', true).css('opacity', '0.5');
    } else {
        reqElems.forEach(function(elem){
            $(elem).prop('required', true).prop('readonly', false).css('opacity', '1.0').val('');
        });
        $('#op-start-type option:contains("bootstrap")').prop('selected',false);
        $('#op-start-type').prop('readonly', false).css('opacity', '1.0');
    }
}

function showNetworkAddMode(){
    openTab(null, 'network-add', 'network-tabcontent', 'network-tablinks');
    $('#network-add-link').addClass("active-tab");
    $('#networkNewName').val('');
    $('#hostTbl tbody tr').removeClass('selected');

    $('#networkModeDescription').html("All hosts running the CAgent are shown in the table below.  " +
        "Click on rows to add them to a host group network. Then, name your network and save it to continue.");
    //Redraw host table to remove filtering
    $('#hostTbl').DataTable().draw();
}

function handleNetworkViewModeAction(){
    openTab(null, 'network-select', 'network-tabcontent', 'network-tablinks');
    $('#network-select-link').addClass("active-tab");
    $('#deleteNetwork').attr("disabled",  $('#networks option').length == 1);
    $('#networkModeDescription').html("The list of hosts in the selected network is shown below.");
    $('#hostTbl tbody tr').removeClass('selected');
    // Redraw to only display hosts for the selected group
    $('#hostTbl').DataTable().draw();
}

function handleDeleteAdversaryAction(){
    let adversaryId = $('#adversaries option:selected').attr('value');
    $.ajax({
       url: '/plugin/adversary/gui',
       type: 'DELETE',
       data: {'index':'adversary', 'id':adversaryId},
       success:function(data) {
           flash('flash-adversary', data);
           ["#adv-", "#op-adv-"].forEach(elem => { $(elem + adversaryId).remove();});
           delete adversaries_by_id[adversaryId];
           Object.keys(adversaries_by_id).length ? displayAdversary(): showAdversaryAddMode();
       }
    });
}


function displayAdversary(){
    openTab(null, 'adv-select', 'adv-tabcontent', 'adv-tablinks');
    $('#adv-select-link').addClass("active-tab");
    $("#adv-common").detach().appendTo($('#chosen-adv-select'));
    ["#artifactlists", "#exfil_method", "#exfil_port", "#exfil_address"].forEach(id => { $(id).val('').hide().attr("disabled", false);});
    let selectedAdvId = $("#adversaries option:selected").val();
    $( ".slides" ).sortable("disable");

    $('#advTbl').DataTable().columns().every(function(){
        if(this.header().innerHTML == "Add"){
            this.visible(false);
        }
    }).draw();
    if(selectedAdvId){
        let adv = adversaries_by_id[selectedAdvId];
        $("#deleteAdversary").attr("disabled", adv['protected']);
        $('#advModeDescription').html("The profile for the selected adversary is shown below.");

        //Display the steps in the selected adversary
        $('#chosenAdvSteps').empty();
        for(let index = 0; index < adv.steps.length; index++) addAdversaryStep(adv.steps[index]);

        artifactlist = '';
        if(adv.artifact_list.length) artifactlist = adv.artifact_list[0];
        if(artifactlist) $("#artifactlists").val(artifactlist).attr("disabled", true).show();
        if(adv.exfil_method) $('#exfil_method').val(adv.exfil_method).attr("disabled", true).show();
        if(adv.exfil_port) $('#exfil_port').val(adv.exfil_port).attr("disabled", true).show();
        if(adv.exfil_address) $('#exfil_address').val(adv.exfil_address).attr("disabled", true).show();
    }else{
        $('#advModeDescription').html("Select an adversary to view its profile.");
        $("#deleteAdversary").attr("disabled", true);
    }
}

function showAdversaryAddMode(){
    openTab(null, 'adv-add', 'adv-tabcontent', 'adv-tablinks');
    $('#adv-add-link').addClass("active-tab");
    $("#adv-common").detach().appendTo($('#chosen-adv-add'));
    ["#artifactlists", "#exfil_method", "#exfil_port", "#exfil_address"].forEach(id => { $(id).val('').show().attr("disabled", false);});
    $( ".slides" ).sortable( "enable" );
    $('#chosenAdvSteps').empty();

    $('#advModeDescription').html("Create an adversary to emulate. Add the steps (behaviors) you want your adversary\n" +
        "                        to know about. When you run your adversary, their steps will be fed into\n" +
        "                        the CALDERA planner, which will determine the best way to move through a given network.\n" +
        "                        Not all steps are likely to run every operation nor is their order deterministic.\n" +
        "                        You can skip this section and use one of CALDERA's built-in adversaries.");
    //Ensure the add column in the table is visible so the user can add steps to the profile
    $('#advTbl').DataTable().columns().every(function(){
        if(this.header().innerHTML == "Add"){
            this.visible(true);
        }
    }).draw();
}

/*
 * This function implements the row filtering logic for all rows
 * in the DataTable.  Note that one function manages all defined
 * DataTables.
 */
function dataTableSelectionFilter(settings, data, dataIndex) {
    if(settings.nTable.id == 'hostTbl'){
       let selectedNetworkId = $("#networks option:selected").val();
       let inViewNetworkMode = $('#networks').is(':visible');
       if(selectedNetworkId && inViewNetworkMode){
           let hostsInNetwork = networks_by_id[selectedNetworkId].hosts;
           return hostsInNetwork.includes(data[2]);
       }else{
           //If at least one host is selected, only show other hosts from the same domain
           let selectedHosts = $('#hostTbl').DataTable().rows('.selected').data();
           if(selectedHosts.length){
               let domain = selectedHosts[0][3];
               return domain == data[3];
           }
       }
   }else if(settings.nTable.id == 'advTbl'){
       let selectedAdvId = $("#adversaries option:selected").val();
       let inViewAdvMode = $('#adversaries').is(':visible');
       if(selectedAdvId && inViewAdvMode){
           stepId = $('#advTbl').DataTable().row(dataIndex).id();
           stepId = stepId.substring(stepId.lastIndexOf("-") + 1);
           let stepsInAdv = adversaries_by_id[selectedAdvId].steps;
           return stepsInAdv.includes(stepId)
       }
   }
   return true;
}

function init(){
    $('#advTbl').DataTable();
    let hostTbl = $('#hostTbl').DataTable({
        columnDefs: [{
            orderable: false,
            className: 'select-checkbox',
            targets: 0
        }],
        select: {
            style: 'os',
            selector: 'td:first-child'
        },
        order: [
            [1, 'asc']
        ]
    });
    /*
     * Selecting a host in the hostTbl is only allowed when creating
     * a new network or editing an existing network.
     */
    $('#hostTbl tbody').on( 'click', 'tr', function () {
        let inAddNetworkMode = $('#saveNetwork').is(':visible');
        if(inAddNetworkMode){
            $(this).toggleClass('selected');
            let hostTbl = $('#hostTbl').DataTable();
            let numSelectedHosts = hostTbl.rows('.selected').data().length;
            /*
             * only redraw the table when the first host is selected or deselected
             * so that hosts from other domains are filtered or in the deselected case
             * to reshow all hosts.
             */
            if(numSelectedHosts == 0 || numSelectedHosts == 1) hostTbl.draw();
        }
    });
    $.fn.dataTableExt.afnFiltering.push(dataTableSelectionFilter);
    ['#network-add-form', '#network-select-form'].forEach(elem => { $(elem).submit(handleNetworkFormSubmit);});
    ['#adv-add-form', '#adv-select-form'].forEach(elem => { $(elem).submit(handleAdversaryFormSubmit);});
    /*
     * This registers the function that removes a step from the chosenAdvStep
     * list when the close button on the step is clicked.
     */
    $("#chosenAdvSteps").delegate(".step-close", "click", function() {
        $(this).parent().remove();
        checkAdversaryStepDependencies();
    });
    showNetworkAddMode();
    showAdversaryAddMode();
    $('#op-form').submit(handleOperationsFormSubmit);
    $('#opVisuals > span').click(function() {
        $('#visual0').slideToggle(600);
        $('#visual1').slideToggle(600);
    });
    // Modify Attack Plan Required Options
    $('#op-network').on('change', handleOperationNetworkChange);
    refresh();
}

function refreshInitialFootprintHosts(){
    let selectedNetId = $('#op-network option:selected').val();

    if(selectedNetId){
        let selectedInitialFootprint = $('#op-start-host option:selected').val();
        let selectedNetwork = networks_by_id[selectedNetId];

        //Initial footprint drop down should only contain the hosts from the selected network
        $('#op-start-host').find('option').remove();
        let hostTbl = $('#hostTbl').DataTable();
        hostTbl.rows().every(function (rowIndex, tableLoop, rowLoop){
            let host = this.data();
            if(selectedNetwork.hosts.includes(host[2])){
                $("#op-start-host").append(new Option(host[1], host[2]));
            }
        });

        // Ensure the selected option that determines the host that will be the initial footprint is maintained
        if(selectedInitialFootprint &&
                $("#op-start-host option[value='" + selectedInitialFootprint + "']").length > 0){
            $("#op-start-host").val(selectedInitialFootprint);
        }else{
            $('#op-start-host option')[0].selected = true;
        }
    }
}

function deleteOldOperation(){
    $.ajax({
		url: '/plugin/adversary/gui',
		type: 'DELETE',
		data: {
		    'index': 'operation',
		    'id': $('#ops option:selected').attr('value')},
        success:function(data) {
            var selectedIndex = $('#ops').prop('selectedIndex');
            if(selectedIndex > 1){
                $('#ops option:selected').remove();
                $('#ops').prop('selectedIndex', selectedIndex - 1);
                refresh();
            } else {
                if($('#ops option').length > 2){
                    $('#ops option:selected').remove();
                    $('#ops').prop('selectedIndex', selectedIndex);
                    refresh();
                } else
                    location.reload(true);
            }
        }
	});
}

function cancelOperation() {
    $.ajax({
        url: '/plugin/adversary/gui',
        type: 'PATCH',
        data: {
            'index': 'operation',
            'id': $('#ops option:selected').attr('value'),
        },
        success:function(data) {
            refresh();
        }
    });
};

function refreshNetworkHostsTable(data){
    //convert the list of hosts to a dictionary
    let hosts_by_ids = data.hosts.reduce((obj, item) => {
        obj[item.id] = item;
        return obj;
    }, {});

    let hostTbl = $('#hostTbl').DataTable();
    let deleted_hosts = [];
    hostTbl.rows().every(function (rowIndex, tableLoop, rowLoop){
        let host = this.data();
        let host_id = host[2];
        if(host_id in hosts_by_ids){
            host[0] = "";
            host[1] = hosts_by_ids[host_id].hostname;
            host[3] = hosts_by_ids[host_id].domain.windows_domain;
            host[4] = hosts_by_ids[host_id].last_seen;
            delete hosts_by_ids[host_id];
            this.invalidate();
        }else{
            deleted_hosts.push(this);
        }
    });
    for(let host_id in hosts_by_ids) {
        let row = hosts_by_ids[host_id];
        hostTbl.row.add(["", row.hostname, row.id, row.domain.windows_domain, row.last_seen]);
    }
    deleted_hosts.forEach(function(row){
        hostTbl.row(row.node()).remove();
    });

    refreshInitialFootprintHosts();
    hostTbl.draw();
}

function refreshStreamResultsView(data){
    // update activity section
    if (data.chosen != null) {
        let op = data.chosen;
        $("#deleteOperation-btn").css("display", "none");
        $("#cancelOperation-btn").css("display", "none");
        if(op.status !== 'complete') {
            document.getElementById("dash-status-title").innerHTML = 'STATUS';
            document.getElementById("dash-status").innerHTML = op.status;
            if(op.status !== "cancelling")
                $("#cancelOperation-btn").css("display", "inline-block");
        }else{
            document.getElementById("dash-status-title").innerHTML = 'ENDED';
            document.getElementById("dash-status").innerHTML = op.end_time;
            $('#control-box').css("display", "none");
        }
        if(op.status === 'complete' || op.status === 'failed'){
            $("#deleteOperation-btn").css("display", "inline-block");
        }

        document.getElementById("dash-start").innerHTML = op.start_time;
        document.getElementById("dash-network").innerHTML = op.network.name;
        document.getElementById("dash-adversary").innerHTML = op.adversary.name;
        document.getElementById("dash-compromised").innerHTML = op.known_credentials.length;

        //steps
        let selected_steps = [];
        $(".panel:visible").each(function(){
            selected_steps.push($(this).attr("id"));
        });

        let stepper = document.getElementById('stepper');
        stepper.innerHTML = null;
        for (let i = 0; i < op.performed_steps.length; i++) {
            let id = data.chosen.id + "_" + i;
            let display = "";
            if(selected_steps.includes(id)){
                display = "style='display: block'";
            }
            let contents =
                "<button class=\"accordion step-" + op.performed_steps[i].status + " \">  " + op.performed_steps[i].jobs[0].create_time + ' ' + op.performed_steps[i].description + "</button>\n";

            contents += "<div class=\"panel\" " + display + " id=\"" + id + "\" style=\"text-align: left;\">\n";
            for(let j = 0; j < op.performed_steps[i].jobs.length; j++){
                if(op.performed_steps[i].jobs[j].cmd){
                    contents +=
                    "<strong>Command Line:</strong>" +
                    "<pre style=\"text-align:left\">" +
                    "\n" + op.performed_steps[i].jobs[j].cmd +
                    "</pre>";
                }

                if(op.performed_steps[i].jobs[j].stdin){
                    contents +=
                    "<div style=\"float: right; width: 30%;\"><strong>StdIn:</strong>" +
                    "<pre style=\"text-align:left\">" +
                    "\n" + op.performed_steps[i].jobs[j].stdin +
                    "</pre></div>";
                }

                if(op.performed_steps[i].jobs[j].stdout){
                    contents +=
                    "<div style=\"display:block\"><strong>StdOut:</strong>" +
                    "<pre style=\"text-align:left\">" +
                    "\n" + op.performed_steps[i].jobs[j].stdout +
                    "</pre></div>";
                }
            }
            contents += "</div>\n";
            stepper.innerHTML += contents;
        }

        //accordion
        let acc = document.getElementsByClassName("accordion");
        let i;
        for (i = 0; i < acc.length; i++) {
            acc[i].addEventListener("click", function () {
                this.classList.toggle("active");
                let panel = this.nextElementSibling;
                if (panel.style.display === "block") {
                    panel.style.display = "none";
                } else {
                    panel.style.display = "block";
                }
            });
        }
    }
}

function refresh(){
    $.ajax({
        url: '/operation/refresh',
        type: 'POST',
        data: {'id': $('#ops option:selected').attr('value')},
        success:function(data) {
            //Convert the return list of networks to a dictionary of networks keyed by network id
            networks_by_id = data.networks.reduce((obj, item) => {
                obj[item.id] = item;
                return obj;
            }, {});

            adversaries_by_id = data.adversaries.reduce((obj, item) => {
                obj[item.id] = item;
                return obj;
            }, {});

            steps_by_id = data.steps.reduce((obj, item) => {
                obj[item.id] = item;
                return obj;
            }, {});

            domains_by_id = data.domains.reduce((obj, item) => {
                obj[item.id] = item;
                return obj;
            }, {});

            refreshNetworkHostsTable(data);
            refreshStreamResultsView(data);
            refreshGraph(data);
        }
    });
}

function handleShowAdvTblStepDetailsDlgAction(id) {
    document.getElementById("modal-description").innerHTML = steps_by_id[id].summary;
}

function addAdversaryStep(id) {
    let inAdvViewMode = $('#adversaries').is(':visible');
    let name = steps_by_id[id].name;

    let closeBtn = '';
    if(!inAdvViewMode){
        closeBtn = '<span class="step-close">&times;</span>';
    }

    if($("#chosenAdvSteps").find("li#" + id).length > 0){
        alert("This adversary already contains the step " + name + ".");
        return;
    }
    $("#chosenAdvSteps").append('<li id="'+id+'" class="slide step-li">' + name + closeBtn + '</li>');
    document.getElementById(id).setAttribute("step", id);
    checkAdversaryStepDependencies();
}


function checkAdversaryStepDependencies(){
    let steps_element = $("#chosenAdvSteps li");

    // Get the existing post-conditions
    let provided = new Set(['oprat']);
    for (let x = 0; x < steps_element.length; x++) {
		getProvidedPostconditions(steps_element.eq(x).attr('id'), provided);
	}

    // Find the missing requirements
    let missing_reqs = new Set([]);
    let required_by = {};
    for (let y = 0; y < steps_element.length; y++) {
        let step = steps_by_id[steps_element.eq(y).attr('id')];
        for ( let z = 0; z < step.requirement_terms.length; z++){
            let predicate = step.requirement_terms[z].predicate;
            if (!ignore_predicate.has(predicate) && !provided.has(predicate)) {
                missing_reqs.add(predicate);
                if (predicate in required_by)
                    required_by[predicate].add(step);
                else
                    required_by[predicate] = new Set([step]);
            }
        }
    }

    if(Object.keys(provided_by).length == 0)
        provided_by = generateProvidedByPostConditions();

    // Update UI
    let reqs_list = $("#missingAdvStepsReqs");
    reqs_list.empty();
    for (let m of missing_reqs) {
         reqs_list.append('<li id="'+m+'" class="missing-slide"><u>' +
             required_by[m].values().next().value.name + '</u> requires object "' + m + '", try adding one of the below steps: ' +
             '<ul>' + set_to_list(provided_by[m]) + '</ul></li>');
    }
}

function set_to_list(l) {
    let list_str = '';
    for (let e of l) {
        list_str = list_str + '<li>' + e.name + '</li>';
    }
    return list_str
}

function getProvidedPostconditions(step_id, provided){
    let step = steps_by_id[step_id];
    for (let x = 0; x < step.add.length; x++){
        let predicate = step.add[x].predicate;
        if(!ignore_predicate.has(predicate))
            provided.add(predicate);
    }
    return provided;
}

function generateProvidedByPostConditions(){
    let gen_provided = {};
    for (let s in steps_by_id) {
        let post_conditions = getProvidedPostconditions(s, new Set());
        for (let p of post_conditions) {
            if (p in gen_provided)
                gen_provided[p].add(steps_by_id[s]);
            else
                gen_provided[p] = new Set([steps_by_id[s]]);
        }
    }
    return gen_provided;
}

// Build Deliver Attack
$('#op-network').on('change', function(e){
    resetOpForm();
    let selectedNetId = $('#op-network option:selected').val();
    let domain = networks_by_id[selectedNetId].domain;
    domain = domains_by_id[domain];
    if(domain.is_simulated) {
        // Simulated environment
        setSimEnvAttrs();
        flash('flash-operation', 'Configured Simulated Network options.');
    } else {
        // Display Part 2 options for Live network Environment
        $('#rat-deployment').css('display', 'block');
        flash('flash-operation', 'Enabling Live Network options.');
    }

    refreshInitialFootprintHosts();
});

// Simple Attack Form Reset
function resetOpForm(){
    // Reset Part 2: Rat Deployment
    $('#rat-deployment').css('display', 'none');
    $('#hidden-op-start-type').prop('disabled', false).val('');
    $('#op-start-type').prop('disabled', false).css('opacity', '1.0');
    $('#op-start-type option')[0].selected = true;
    $('#op-start-rat').prop('disabled', true).css('display', 'none');
    $('#op-start-rat option')[0].selected = true;

    // Reset Part 3: Initial Foothold
    resetInitialFoothold();
}

function resetInitialFoothold(){
    $('#initial-foothold').css('display', 'none');
    $('.radio-group').css('display', 'block');
    $('[name=start_user]').prop('required', false).prop('readonly', false).css('display', 'inline-block').val('');
    $('[name=start_password]').prop('required', false).prop('readonly', false).css('display', 'inline-block').val('');
    $('input[name="user_type"]')[0].checked = true;
    $('#op-start-host').css('opacity','1.0');
}

// Builds a sim environment config, only requires user to input
function setSimEnvAttrs(){
    // RAT Deployment Settings Configured and Locked
    $('#rat-deployment').css('display', 'block');
    $('#op-start-type option:contains("bootstrap")').prop('selected', true);
    $('#op-start-type').prop('disabled', true).css('opacity', '0.5');
    $('#hidden-op-start-type').prop('disabled', false).val('bootstrap');

    // Set Initial Foothold Values
    $('#initial-foothold').css('display', 'block');
    $('[name=start_user]').prop('required', false).prop('readonly', true).css('display', 'none').val('sim\\sim');
    $('[name=start_password]').prop('required', false).prop('readonly', true).css('display', 'none').val('sim\\sim');
    $('.radio-group').css('display', 'none');
}

// Phase 2: RAT Deployment
$('#op-start-type').on('change', function(e) {
    // make phase 3 available
    $('#op-start-rat').prop('disabled', true).css('display', 'none');
    resetInitialFoothold();
    if(e.target.value == "existing") {
        existingRatStart();
        flash('flash-operation', 'Enabling EXISTING RAT deployment options.');
    } else if (e.target.value == "wait") {
        waitRatStart();
        flash('flash-operation', 'Enabling WAIT deployment options.');
    } else {
        $('#initial-foothold').css('display','block');
        flash('flash-operation', 'Enabling BOOTSTRAP deployment options.');
    }
});

$('input[name="user_type"]').change(function(e){
    if(e.target.id == "system-credentials"){
        $("[name='start_user']").prop("readonly", true).css("opacity","0.5").val("nt authority\\system");
        $("[name='start_password']").prop("readonly", true).css("opacity","0.5").val("");
    } else if(e.target.id == "user-credentials") {
        $("[name='start_user']").prop("readonly", false).css("opacity", "1.0").val("");
        $("[name='start_password']").prop("readonly", false).css("opacity", "1.0").val("");
    } else {
        $("[name='start_user']").prop("readonly", true).css("opacity","0.5").val("");
        $("[name='start_password']").prop("readonly", true).css("opacity","0.5").val("");
    }
});

function controlOp(mode){
    let op = $('#ops option:selected').attr('value');
    $.ajax({
            url: `/op/control`,
            type: 'post',
            data: {'id': op, 'mode': mode},
            success: function (data) {
                getOpState();
            }
        });
}

function getOpState() {
    let op = $('#ops option:selected').attr('value');
    $.ajax({
            url: `/op/control`,
            type: 'post',
            data: {'id': op, 'mode': 'state'},
            success: function (data) {
                if (data['result'] === 'PAUSED'){
                    $('#control-play').css('display','');
                    $('#control-pause').css('display','none');
                }
                if (data['result'] === 'RUNNING') {
                    $('#control-play').css('display','none');
                    $('#control-pause').css('display','');
                }
                document.getElementById('control-state').innerHTML = data['result']
            }
        });
}

function waitRatStart() {
    $('#initial-foothold').css('display','block');
    $('[name=start_user]').prop('required', false).prop('readonly', true).css('display', 'none');
    $('[name=start_password]').prop('required', false).prop('readonly', true).css('display', 'none');
    $('.radio-group').css('display', 'none');
}

// set up the existing RAT options
function existingRatStart() {
    $('#op-start-rat').prop('disabled', false).css('display', 'inline-block');
    $('#initial-foothold').css('display','block');
    $('#op-start-rat option')[0].selected = true;
    $('[name=start_user]').prop('required', false).prop('readonly', true).css('display', 'none');
    $('[name=start_password]').prop('required', false).prop('readonly', true).css('display', 'none');
    $('.radio-group').css('display', 'none');
}

// set the existing RAT host variable
$('#op-start-rat').on('change', function (e) {
    let selectedRatHost = $('#op-start-rat option:selected').prop('label');
    $('#op-start-host option[value="' + selectedRatHost + '"]').prop('selected',true);
    $('#op-start-host').css('opacity', '0.5');
});

function downloadLogs(type) {
    let operation = $('#ops option:selected').attr('value');
    if(operation == '') {
        alert("You must select an operation first!");
    } else {
        window.location.href = '/adversary/logs/'+type+'?id=' + operation;
    }
}

// preview windows for cagent installation script
let cagentInstallPreviewDisplayed = false;
function previewRender() {
    if (cagentInstallPreviewDisplayed) {
        $("#cagentInstallScriptPreview").html("");
        cagentInstallPreviewDisplayed = false;
    } else {
        $.ajax({
            url: `/file/render`,
            type: 'post',
            data: {},
            headers: {file: 'Install-Cagent.ps1'},
            success: function (data) {
                previewPre = `<pre><code style="font-size:12px">${data}</code></pre>`;
                $("#cagentInstallScriptPreview").html(previewPre);
                cagentInstallPreviewDisplayed = true;
            }
        });
    }
}
