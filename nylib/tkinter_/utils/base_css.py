rgb = lambda r, g, b: f"#{int(r):02x}{int(g):02x}{int(b):02x}"
ROOT_VARS = {
    'color-primary-1': rgb(51.2, 126.4, 204),
    'color-primary-2': rgb(121.3, 187.1, 255),
    'color-primary-3': rgb(159.5, 206.5, 255),
    'color-primary-4': rgb(197.7, 225.9, 255),
    'color-primary-5': rgb(216.8, 235.6, 255),
    'color-primary-6': rgb(235.9, 245.3, 255),

    'color-success-1': rgb(82.4, 155.2, 46.4),
    'color-success-2': rgb(148.6, 212.3, 117.1),
    'color-success-3': rgb(179, 224.5, 156.5),
    'color-success-4': rgb(209.4, 236.7, 195.9),
    'color-success-5': rgb(224.6, 242.8, 215.6),
    'color-success-6': rgb(239.8, 248.9, 235.3),

    'color-warning-1': rgb(184, 129.6, 48),
    'color-warning-2': rgb(237.5, 189.9, 118.5),
    'color-warning-3': rgb(242.5, 208.5, 157.5),
    'color-warning-4': rgb(247.5, 227.1, 196.5),
    'color-warning-5': rgb(250, 236.4, 216),
    'color-warning-6': rgb(252.5, 245.7, 235.5),

    'color-danger-1': rgb(196, 86.4, 86.4),
    'color-danger-2': rgb(248, 152.1, 152.1),
    'color-danger-3': rgb(250, 181.5, 181.5),
    'color-danger-4': rgb(252, 210.9, 210.9),
    'color-danger-5': rgb(253, 225.6, 225.6),
    'color-danger-6': rgb(254, 240.3, 240.3),

    'color-info-1': rgb(115.2, 117.6, 122.4),
    'color-info-2': rgb(177.3, 179.4, 183.6),
    'color-info-3': rgb(199.5, 201, 204),
    'color-info-4': rgb(221.7, 222.6, 224.4),
    'color-info-5': rgb(232.8, 233.4, 234.6),
    'color-info-6': rgb(243.9, 244.2, 244.8),

    'color-button-normal-bg-primary': 'var:color-primary-6',
    'color-button-normal-fg-primary': 'var:color-primary-1',
    'color-button-normal-border-primary': 'var:color-primary-1',

    'color-button-hover-bg-primary': 'var:color-primary-2',
    'color-button-hover-fg-primary': 'var:color-primary-6',
    'color-button-hover-border-primary': 'var:color-primary-1',

    'color-button-active-bg-primary': 'var:color-primary-1',
    'color-button-active-fg-primary': 'var:color-primary-6',
    'color-button-active-border-primary': 'var:color-primary-1',

    'color-button-normal-bg-success': 'var:color-success-6',
    'color-button-normal-fg-success': 'var:color-success-1',
    'color-button-normal-border-success': 'var:color-success-1',

    'color-button-hover-bg-success': 'var:color-success-2',
    'color-button-hover-fg-success': 'var:color-success-6',
    'color-button-hover-border-success': 'var:color-success-1',

    'color-button-active-bg-success': 'var:color-success-1',
    'color-button-active-fg-success': 'var:color-success-6',
    'color-button-active-border-success': 'var:color-success-1',

    'color-button-normal-bg-warning': 'var:color-warning-6',
    'color-button-normal-fg-warning': 'var:color-warning-1',
    'color-button-normal-border-warning': 'var:color-warning-1',

    'color-button-hover-bg-warning': 'var:color-warning-2',
    'color-button-hover-fg-warning': 'var:color-warning-6',
    'color-button-hover-border-warning': 'var:color-warning-1',

    'color-button-active-bg-warning': 'var:color-warning-1',
    'color-button-active-fg-warning': 'var:color-warning-6',
    'color-button-active-border-warning': 'var:color-warning-1',

    'color-button-normal-bg-danger': 'var:color-danger-6',
    'color-button-normal-fg-danger': 'var:color-danger-1',
    'color-button-normal-border-danger': 'var:color-danger-1',

    'color-button-hover-bg-danger': 'var:color-danger-2',
    'color-button-hover-fg-danger': 'var:color-danger-6',
    'color-button-hover-border-danger': 'var:color-danger-1',

    'color-button-active-bg-danger': 'var:color-danger-1',
    'color-button-active-fg-danger': 'var:color-danger-6',
    'color-button-active-border-danger': 'var:color-danger-1',

    'color-button-normal-bg-info': 'var:color-info-6',
    'color-button-normal-fg-info': 'var:color-info-1',
    'color-button-normal-border-info': 'var:color-info-1',

    'color-button-hover-bg-info': 'var:color-info-2',
    'color-button-hover-fg-info': 'var:color-info-6',
    'color-button-hover-border-info': 'var:color-info-1',

    'color-button-active-bg-info': 'var:color-info-1',
    'color-button-active-fg-info': 'var:color-info-6',
    'color-button-active-border-info': 'var:color-info-1',

    'color-button-disabled-border': 'var:color-info-2',
    'color-button-disabled-bg': 'var:color-info-3',
    'color-button-disabled-fg': 'var:color-info-4',
}

ROOT_CSS = {
    'background': 'white',
    'font-family': 'TkDefaultFont',
    'font-size': 12,
    'font-style': 'normal',
    'border-width': 2,
    'border-radius': 0,
    'border-color': 'black',
    'button-border-width': 0,
    'button-border-radius': 5,
    'button-padding': 10,
    'border-title-foreground': 'var:color-info-1',
    'border-title-font': ('TkDefaultFont', 10, ''),
    'scrollbar-width': '5',
    'scrollbar-color': 'gray',
    'scrollbar-min-height': 20,
    'input-border-width': 2,
    'input-border-radius': 0,
    'input-border-color': 'var:color-info-2',
    'input-padx': 10,
    'input-pady': 5,
    'seperator-padx': 5,
    'seperator-pady': 5,
    'seperator-color': 'var:color-info-2',
}
