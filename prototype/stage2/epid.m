% get packet dst endpoint id
function ep = epid(id)

global PKT;

if PKT.tcp(id)
    txt = sprintf('tcp %u:%u', PKT.dstip(id), PKT.dstport(id));
else
    txt = sprintf('udp %u:%u', PKT.dstip(id), PKT.dstport(id));
end

if isKey(PKT.flowmap, txt)
    ep = PKT.flowmap(txt);
else
    ep = size(PKT.flows, 2) + 1;
    PKT.flowmap(txt) = ep;
    
    PKT.flows(ep).ip = PKT.dstip(id);
    PKT.flows(ep).port = PKT.dstport(id);
    PKT.flows(ep).packets = [];
end
