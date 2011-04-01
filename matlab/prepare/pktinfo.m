% Group raw packet information into flows
% For each flow divide packets into windows
% For each window compute KISS signature + basic info
function pktinfo = pktinfo(pkts, b, N, C)

global PKT;

% KISS params
PKT.b = b;                % bits in byte
PKT.N = N;                % bytes in packets
PKT.G = (ceil(8/b) * N);  % number of groups in each packet
PKT.C = C;                % number of packets in window
PKT.K = 2 ^ b;            % number of counters in window
PKT.E = C / 2^b;          % expected number of occurances

% for easier reading
PKT.id = pkts(:, 1);
PKT.real_id = pkts(:, 2);
PKT.time = pkts(:, 3) * 1000000 + pkts(:, 4);
PKT.size = pkts(:, 5);
PKT.srcip = pkts(:, 6);
PKT.srcport = pkts(:, 7);
PKT.dstip = pkts(:, 8);
PKT.dstport = pkts(:, 9);
PKT.tcp = pkts(:, 10);
PKT.tcpseq = pkts(:, 11);
PKT.payload = pkts(:, 12:11 + PKT.G);

% flow info
PKT.flowmap = containers.Map('KeyType', 'char', 'ValueType', 'uint32');
PKT.flows = [];

% collect packets into flows
for i = 1:size(pkts, 1)
    if PKT.tcp(i)
        [ epid1, epid2 ] = ep_ids(i);

        len = size(PKT.flows(epid1).packets, 2) + 1;
        PKT.flows(epid1).packets(len) = i;
        if (mod(len, C) == 0)
            window(epid1);
        end
        
        len = size(PKT.flows(epid2).packets, 2) + 1;
        PKT.flows(epid2).packets(len) = i;
        if (mod(len, C) == 0)
            window(epid2);
        end
    else
        fid = flow_id(i);
        
        len = size(PKT.flows(fid).packets, 2) + 1;
        PKT.flows(fid).packets(len) = i;
        if (mod(len, C) == 0)
            window(fid);
        end
    end
end

if ~isfield(PKT.flows, 'windows')
    error('no packet windows - dump too short?')
end

pktinfo = rmfield(PKT, {'flows' 'flowmap'});
pktinfo.flows = struct('type', {}, 'ip', {}, 'port', {}, 'windows', {});

% copy only flows having at least one window
for i = 1:size(PKT.flows, 2)
    if size(PKT.flows(i).windows, 2) == 0
        continue
    end
    
    pktinfo.flows(end+1) = rmfield(PKT.flows(i), 'packets');
end
