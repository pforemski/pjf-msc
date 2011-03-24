% get packet endpoints ids
function [ epid1, epid2 ] = ep_ids(id)

global PKT;

% yuck
txt = sprintf('tcp src %u:%u', PKT.srcip(id), PKT.srcport(id));
if isKey(PKT.flowmap, txt)
    epid1 = PKT.flowmap(txt);
else
    epid1 = size(PKT.flows, 2) + 1;
    PKT.flowmap(txt) = epid1;
    
    PKT.flows(epid1).type = 'tcp src endpoint';
    PKT.flows(epid1).ip = PKT.srcip(id);
    PKT.flows(epid1).port = PKT.srcport(id);
    PKT.flows(epid1).packets = [];
end

txt = sprintf('tcp dst %u:%u', PKT.dstip(id), PKT.dstport(id));
if isKey(PKT.flowmap, txt)
    epid2 = PKT.flowmap(txt);
else
    epid2 = size(PKT.flows, 2) + 1;
    PKT.flowmap(txt) = epid2;
    
	PKT.flows(epid2).type = 'tcp dst endpoint';
    PKT.flows(epid2).ip = PKT.dstip(id);
    PKT.flows(epid2).port = PKT.dstport(id);
    PKT.flows(epid2).packets = [];
end
