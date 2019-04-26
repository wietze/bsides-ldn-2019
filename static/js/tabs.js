function openTab(evt, identifier, tabclass = "tabcontent", tablinks = "tablinks", displayType="block") {
    setLinksToUnselected(tablinks, tabclass);
    document.getElementById(identifier).style.display = displayType;
    if(evt) evt.currentTarget.className += " active-tab";
}

function setLinksToUnselected(links, tabs){
    let i, tabcontent, tablinks;
    tabcontent = document.getElementsByClassName(tabs);
    for (i = 0; i < tabcontent.length; i++) {
        tabcontent[i].style.display = "none";
    }
    tablinks = document.getElementsByClassName(links);
    for (i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(" active-tab", "");
    }
}

function openSubTab(evt, identifier) {
    setLinksToUnselected("subtablinks", "subtabcontent");
    document.getElementById(identifier).style.display = "block";
    evt.currentTarget.className += " active-tab";
}