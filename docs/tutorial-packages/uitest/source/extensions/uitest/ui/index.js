export default {
  async register(ctx) {
    const { h } = ctx.Vue
    const path = '/extensions/uitest'
    if (!ctx.router.hasRoute('tec-tac-uitest')) {
      ctx.router.addRoute({
        path,
        name: 'tec-tac-uitest',
        meta: { title: 'UI Test' },
        component: {
          name: 'TecTacUiTest',
          setup() {
            return () => h('section', [
              h('div', { class: 'phead' }, [
                h('div', [
                  h('span', { class: 'eyebrow' }, 'DYNAMIC MODULE'),
                  h('h1', 'UI Test'),
                  h('p', 'This page was registered at runtime from an installed Tec-Tac extension package.'),
                ]),
              ]),
              h('article', { class: 'card' }, [
                h('div', { class: 'cardhead' }, [
                  h('h3', 'Runtime registration'),
                  h('span', { class: 'pill ok' }, 'LOADED'),
                ]),
                h('dl', { class: 'kvlist' }, [
                  h('dt', 'Module'), h('dd', { class: 'mono' }, ctx.descriptor.id),
                  h('dt', 'Version'), h('dd', { class: 'mono' }, ctx.descriptor.version),
                  h('dt', 'Permission'), h('dd', { class: 'mono' }, 'uitest.read'),
                ]),
              ]),
            ])
          },
        },
      })
    }
    ctx.addNavigation({ label: 'UI Test', icon: 'U', to: path, section: 'Extensions', order: 900 })
  },
}
