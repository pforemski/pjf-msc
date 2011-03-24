function wid = window(fid)
global PKT;

% shortcut to flow info
finfo = PKT.flows(fid);

%
% collect packet info
%
winfo.packets = finfo.packets;
winfo.avgsize = round(mean(PKT.size(winfo.packets)));

% inter-packet time analysis
timediff = diff(PKT.time(winfo.packets));
timediff(timediff > quantile(timediff, 0.90)) = NaN;
winfo.avgtimespace = nanmean(timediff);
winfo.jitter = nanmean(abs(diff(timediff)));

%
% make K counters
%
values = reshape(PKT.payload(winfo.packets,:), 1, PKT.C * PKT.G);
winfo.O = histc(values, 0:PKT.K - 1);

% write back to flow info
if ~isfield(finfo, 'windows')
	wid = 1;
else
    wid = size(finfo.windows, 2) + 1;
end

PKT.flows(fid).windows(wid) = winfo;
PKT.flows(fid).packets = [];
